/*
 * Copyright (C) 2019 Vincenzo Maffione. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>

static int
bpfhv_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct bpfhv_info *bi = netdev_priv(ifp);
	unsigned int i;
	enum txrx t;

	if (netif_running(bi->netdev))
		bpfhv_close(bi->netdev);

	/* Enable or disable flags and callbacks in na and ifp. */
	if (onoff) {
		nm_set_native_flags(na);
		for_rx_tx(t) {
			/* Switch mode for hardware rings. */
			for (i = 0; i < nma_get_nrings(na, t); i++) {
				struct netmap_kring *kring = NMR(na, t)[i];

				if (!nm_kring_pending_on(kring))
					continue;
				kring->nr_mode = NKR_NETMAP_ON;
				nm_prinf("kring %s goes on", kring->name);
			}
		}
	} else {
		for_rx_tx(t) {
			/* Switch mode for hardware rings. */
			for (i = 0; i < nma_get_nrings(na, t); i++) {
				struct netmap_kring *kring = NMR(na, t)[i];

				if (!nm_kring_pending_off(kring))
					continue;
				kring->nr_mode = NKR_NETMAP_OFF;
				nm_prinf("kring %s goes off", kring->name);
			}
		}
		nm_clear_native_flags(na);
	}

	if (netif_running(bi->netdev))
		bpfhv_open(bi->netdev);

	return (0);
}

static unsigned int
bpfhv_netmap_tx_clean(struct bpfhv_txq *txq, unsigned int progid)
{
	struct bpfhv_tx_context *ctx = txq->ctx;
	unsigned int count = 0;

	for (;;) {
		int ret;

		ret = BPF_PROG_RUN(txq->bi->progs[progid],
				/*ctx=*/ctx);
		if (ret <= 0) {
			if (ret < 0) {
				nm_prerr("netmap tx reclaim failed");
			} else {
				/* No more buffers to reclaim. */
			}
			break;
		}

		txq->tx_free_bufs += ctx->num_bufs;
		count += ctx->num_bufs;
	}

	return count;
}

/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
bpfhv_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;	/* index into the netmap ring */
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;

	/* device-specific */
	struct bpfhv_info *bi = netdev_priv(ifp);
	struct bpfhv_txq *txq = bi->txqs + ring_nr;
	struct bpfhv_tx_context *ctx = txq->ctx;
	unsigned int count;

	/*
	 * First part: process new packets to send.
	 */

	if (!netif_carrier_ok(ifp)) {
		return 0;
	}

	nm_i = kring->nr_hwcur;
	if (nm_i != head) {	/* we have new packets to send */
		bool kick = false;

		for (; nm_i != head && txq->tx_free_bufs > 0; ) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			u_int len = slot->len;
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);

			/* device-specific */
			int ret;

			NM_CHECK_ADDR_LEN(na, addr, len);

			ctx->packet = (uintptr_t)slot;
			ctx->bufs[0].paddr = (uintptr_t)paddr;
			ctx->bufs[0].vaddr = (uintptr_t)addr;
			ctx->bufs[0].len = len;
			ctx->bufs[0].cookie = (uintptr_t)slot;
			ctx->num_bufs = 1;
			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED | NS_MOREFRAG);

			ret = BPF_PROG_RUN(bi->progs[BPFHV_PROG_TX_PUBLISH], /*ctx=*/ctx);
			if (ret) {
				nm_prerr("netmap txp failed --> %d", ret);
				break;
			}

			kick |= (ctx->oflags & BPFHV_OFLAGS_KICK_NEEDED);
			txq->tx_free_bufs --;
			nm_i = nm_next(nm_i, lim);
		}
		kring->nr_hwcur = nm_i;
		if (kick) {
			writel(0, txq->doorbell);
		}
	}

	/*
	 * Second part: reclaim buffers for completed transmissions.
	 */
	count = bpfhv_netmap_tx_clean(txq, BPFHV_PROG_TX_COMPLETE);
	if (count > 0) {
		kring->nr_hwtail += count;
		if (kring->nr_hwtail >= kring->nkr_num_slots) {
			kring->nr_hwtail -= kring->nkr_num_slots;
		}
	}

	if (txq->tx_free_bufs < bi->tx_bufs / 2) {
		ctx->min_completed_bufs = (bi->tx_bufs - txq->tx_free_bufs);
		BPF_PROG_RUN(bi->progs[BPFHV_PROG_TX_INTRS], ctx);
	}

	return 0;
}

static int
bpfhv_netmap_rxp(struct netmap_adapter *na, struct bpfhv_rxq *rxq,
		 struct netmap_slot *slot, bool *kick)
{
	/* Prepare the context for publishing receive buffers. */
	struct bpfhv_rx_context *ctx = rxq->ctx;
	struct bpfhv_rx_buf *rxb = ctx->bufs + 0;
	dma_addr_t dma;
	void *kbuf;
	int ret;

	kbuf = PNMB(na, slot, &dma);
	rxb->cookie = (uintptr_t)(slot);
	rxb->paddr = (uintptr_t)dma;
	rxb->vaddr = (uintptr_t)kbuf;
	rxb->len = NETMAP_BUF_SIZE(na);
	ctx->num_bufs = 1;

	ret = BPF_PROG_RUN(rxq->bi->progs[BPFHV_PROG_RX_PUBLISH], /*ctx=*/ctx);
	if (unlikely(ret)) {
		nm_prerr("Failed to publish netmap RX buf");
		return ret;
	}
	rxq->rx_free_bufs--;
	*kick |= (ctx->oflags & BPFHV_OFLAGS_KICK_NEEDED);

	return 0;
}

/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
bpfhv_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;	/* index into the netmap ring */
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	/* device-specific */
	struct bpfhv_info *bi = netdev_priv(ifp);
	struct bpfhv_rxq *rxq = bi->rxqs + ring_nr;
	struct bpfhv_rx_context *ctx = rxq->ctx;
	bool kick = false;

	if (!netif_carrier_ok(ifp)) {
		return 0;
	}

	/*
	 * First part: import newly received packets.
	 */
	if (netmap_no_pendintr || force_update) {
		int ret;

		for (nm_i = kring->nr_hwtail;;) {
			struct netmap_slot *slot;
			unsigned int j;

			ret = BPF_PROG_RUN(bi->progs[BPFHV_PROG_RX_COMPLETE],
					/*ctx=*/ctx);
			if (ret == 0) {
				/* No more received packets. */
				break;
			}
			if (unlikely(ret < 0)) {
				nm_prerr("netmap rxc failed --> %d", ret);
				break;
			}
			rxq->rx_free_bufs += ctx->num_bufs;

			for (j = 0; j < ctx->num_bufs; j++) {
				slot = ring->slot + nm_i;
				slot->len = ctx->bufs[j].len;
				slot->flags = NS_MOREFRAG;
				nm_i = nm_next(nm_i, lim);
			}
			if (j) {
				slot->flags = 0;
			}
		}
		kring->nr_hwtail = nm_i;
		kring->nr_kflags &= ~NKR_PENDINTR;
	}

	/*
	 * Second part: skip past packets that userspace has released.
	 */
	nm_i = kring->nr_hwcur;
	while (nm_i != head) {
		if (bpfhv_netmap_rxp(na, rxq, ring->slot + nm_i, &kick)) {
			break;
		}
		nm_i = nm_next(nm_i, lim);
	}
	kring->nr_hwcur = nm_i;
	if (kick) {
		writel(0, rxq->doorbell);
	}

	return 0;
}

static bool
bpfhv_netmap_kring_on(struct bpfhv_info *bi, enum txrx t, unsigned int r)
{
	struct netmap_adapter *na = NA(bi->netdev);
	struct netmap_kring **krings;

	if (!nm_native_on(na)) {
		return false;
	}
	krings = (t == NR_RX) ? na->rx_rings : na->tx_rings;

	return krings[r]->nr_mode == NKR_NETMAP_ON;
}

static int
bpfhv_netmap_rxq_attach(struct bpfhv_info *bi, unsigned int r)
{
	struct netmap_adapter *na = NA(bi->netdev);
	struct bpfhv_rxq *rxq = bi->rxqs + r;
	struct netmap_slot *slots;
	unsigned int nm_i;

	if (!bpfhv_netmap_kring_on(bi, NR_RX, r)) {
		return 0;
	}
	slots = na->rx_rings[r]->ring->slot;

	BUG_ON(rxq->rx_free_bufs != bi->rx_bufs);

	for (nm_i = 0; rxq->rx_free_bufs > 1; nm_i++) {
		bool kick = false;

		if (bpfhv_netmap_rxp(na, rxq, slots + nm_i, &kick)) {
			break;
		}
	}

	writel(0, rxq->doorbell);

	return 1;
}

static int
bpfhv_netmap_rxq_detach(struct bpfhv_info *bi, unsigned int r)
{
	struct bpfhv_rxq *rxq = bi->rxqs + r;
	struct bpfhv_rx_context *ctx = rxq->ctx;
	unsigned int count = 0;

	if (!bpfhv_netmap_kring_on(bi, NR_RX, r)) {
		return 0;
	}

	for (;;) {
		int ret;

		ret = BPF_PROG_RUN(bi->progs[BPFHV_PROG_RX_RECLAIM],
				/*ctx=*/ctx);
		if (ret == 0) {
			/* No more buffers to reclaim. */
			break;
		} else if (ret < 0) {
			nm_prerr("netmap rx reclaim failed");
			break;
		}

		rxq->rx_free_bufs += ctx->num_bufs;
		count += ctx->num_bufs;
	}

	if (count) {
		nm_prinf("netmap reclaimed %u rx buffers\n", count);
	}

	if (rxq->rx_free_bufs != bi->rx_bufs) {
		nm_prinf("netmap failed to reclaim %u rx buffers\n",
				(int)bi->rx_bufs - (int)rxq->rx_free_bufs);
	}

	return 1;
}

static int
bpfhv_netmap_txq_detach(struct bpfhv_info *bi, unsigned int r)
{
	struct bpfhv_txq *txq = bi->txqs + r;
	unsigned int count;

	if (!bpfhv_netmap_kring_on(bi, NR_TX, r)) {
		return 0;
	}

	count = bpfhv_netmap_tx_clean(txq, BPFHV_PROG_TX_RECLAIM);
	if (count) {
		nm_prinf("netmap reclaimed %u tx buffers\n", count);
	}

	if (txq->tx_free_bufs != bi->tx_bufs) {
		nm_prinf("netmap failed to reclaim %u tx buffers\n",
				(int)bi->tx_bufs - (int)txq->tx_free_bufs);
	}

	return 1;
}

static int
bpfhv_netmap_config(struct netmap_adapter *na, struct nm_config_info *info)
{
	struct bpfhv_info *bi = netdev_priv(na->ifp);

	info->num_tx_descs = bi->tx_bufs;
	info->num_rx_descs = bi->rx_bufs;
	info->num_tx_rings = bi->num_tx_queues;
	info->num_rx_rings = bi->num_rx_queues;
	info->rx_buf_maxsize = PAGE_SIZE;

	return 0;
}

static void
bpfhv_netmap_attach(struct bpfhv_info *bi)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = bi->netdev;
	na.pdev = &bi->pdev->dev;
	na.na_flags = NAF_MOREFRAG;
	na.num_tx_desc = bi->tx_bufs;
	na.num_rx_desc = bi->rx_bufs;
	na.num_tx_rings = bi->num_tx_queues;
	na.num_rx_rings = bi->num_rx_queues;
	na.rx_buf_maxsize = PAGE_SIZE;
	na.nm_register = bpfhv_netmap_reg;
	na.nm_txsync = bpfhv_netmap_txsync;
	na.nm_rxsync = bpfhv_netmap_rxsync;
	na.nm_config = bpfhv_netmap_config;

	netmap_attach(&na);
}

/* end of file */
