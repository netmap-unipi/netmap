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

	if (netif_running(bi->netdev))
		bpfhv_close(bi->netdev);

	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}
	if (netif_running(bi->netdev))
		bpfhv_open(bi->netdev);

	return (0);
}

/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
bpfhv_netmap_txsync(struct netmap_kring *kring, int flags)
{
	return 0;
}

/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
bpfhv_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	return 0;
}


static int
bpfhv_netmap_rxq_attach(struct bpfhv_info *bi, unsigned int r)
{
	return 0;
}

static int
bpfhv_netmap_rxq_detach(struct bpfhv_info *bi, unsigned int r)
{
	return 0;
}

static int
bpfhv_netmap_txq_detach(struct bpfhv_info *bi, unsigned int r)
{
	return 0;
}

static int
bpfhv_netmap_config(struct netmap_adapter *na, struct nm_config_info *info)
{
	int ret = netmap_rings_config_get(na, info);

	if (ret) {
		return ret;
	}

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
