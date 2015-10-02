/*
 * Copyright (c) 2008 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the
 * GNU General Public License (GPL) Version 2, available from the
 * file COPYING in the main directory of this source tree, or the
 * OpenFabrics.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "ibscif_driver.h"

static LIST_HEAD(listen_list);
DEFINE_SPINLOCK(listen_list_lock);

static int sockaddr_in_to_node_id(struct sockaddr_in addr)
{
	u8 *p = (u8 *)&addr.sin_addr.s_addr;

	if (p[0]==192 && p[1]==0 && p[2]==2 && p[3]>=100 &&
	    p[3]<100+IBSCIF_MAX_DEVICES)
		return (int)(p[3]-100);

	else
		return -EINVAL;
}

static struct sockaddr_in node_id_to_sockaddr_in(int node_id)
{
	struct sockaddr_in addr;
	u8 *p = (u8 *)&addr.sin_addr.s_addr;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = 0;
	addr.sin_port = 0;

	p[0] = 192;
	p[1] = 0;
	p[2] = 2;
	p[3] = 100 + node_id;

	return addr;
}

static void free_cm(struct kref *kref)
{
	struct ibscif_cm *cm_ctx;
	cm_ctx = container_of(kref, struct ibscif_cm, kref);
	if (cm_ctx->conn)
		ibscif_put_conn(cm_ctx->conn);
	kfree(cm_ctx);
}

static inline void get_cm(struct ibscif_cm *cm_ctx)
{
        kref_get(&cm_ctx->kref);
}

static inline void put_cm(struct ibscif_cm *cm_ctx)
{
        kref_put(&cm_ctx->kref, free_cm);
}

static void free_listen(struct kref *kref)
{
	struct ibscif_listen *listen;
	listen = container_of(kref, struct ibscif_listen, kref);
	kfree(listen);
}

static inline void get_listen(struct ibscif_listen *listen)
{
        kref_get(&listen->kref);
}

static inline void put_listen(struct ibscif_listen *listen)
{
        kref_put(&listen->kref, free_listen);
}

static int connect_qp(struct ibscif_cm *cm_ctx)
{
        struct ibscif_qp *qp;
        struct ib_qp_attr qp_attr;
        int qp_attr_mask;
        int err;

        qp = ibscif_get_qp(cm_ctx->qpn);
        if (IS_ERR(qp)) {
                printk(KERN_ERR PFX "%s: invalid QP number: %d\n",
			__func__, cm_ctx->qpn);
                return -EINVAL;
        }

        qp_attr_mask =  IB_QP_STATE |
                        IB_QP_AV |
                        IB_QP_DEST_QPN |
                        IB_QP_ACCESS_FLAGS |
                        IB_QP_MAX_QP_RD_ATOMIC |
                        IB_QP_MAX_DEST_RD_ATOMIC;

        qp_attr.ah_attr.ah_flags = 0;
        qp_attr.ah_attr.dlid = IBSCIF_NODE_ID_TO_LID(cm_ctx->remote_node_id);
        qp_attr.dest_qp_num = cm_ctx->remote_qpn;
        qp_attr.qp_state = IB_QPS_RTS;
        qp_attr.qp_access_flags = IB_ACCESS_LOCAL_WRITE |
                                  IB_ACCESS_REMOTE_WRITE |
                                  IB_ACCESS_REMOTE_READ |
                                  IB_ACCESS_REMOTE_ATOMIC;
        qp_attr.max_rd_atomic = 16; /* 8-bit value, don't use MAX_OR */
        qp_attr.max_dest_rd_atomic = 16; /* 8-bit value, don't use MAX_IR */

        err = ib_modify_qp(&qp->ibqp, &qp_attr, qp_attr_mask);

        if (!err) {
                qp->cm_context = cm_ctx;
		get_cm(cm_ctx);
	}

        ibscif_put_qp(qp);

        return err;
}

static void event_connection_close(struct ibscif_cm *cm_ctx)
{
        struct iw_cm_event event;

        memset(&event, 0, sizeof(event));
        event.event = IW_CM_EVENT_CLOSE;
        event.status = -ECONNRESET;
        if (cm_ctx->cm_id) {
                cm_ctx->cm_id->event_handler(cm_ctx->cm_id, &event);
                cm_ctx->cm_id->rem_ref(cm_ctx->cm_id);
                cm_ctx->cm_id = NULL;
        }
}

static void event_connection_reply(struct ibscif_cm *cm_ctx, int status)
{
        struct iw_cm_event event;

        memset(&event, 0, sizeof(event));
        event.event = IW_CM_EVENT_CONNECT_REPLY;
        event.status = status;
        event.local_addr = *(struct sockaddr_storage *) &cm_ctx->local_addr;
        event.remote_addr = *(struct sockaddr_storage *) &cm_ctx->remote_addr;

        if ((status == 0) || (status == -ECONNREFUSED)) {
                event.private_data_len = cm_ctx->plen;
                event.private_data = cm_ctx->pdata;
        }
        if (cm_ctx->cm_id) {
                cm_ctx->cm_id->event_handler(cm_ctx->cm_id, &event);
		if (status == -ECONNREFUSED) {
			cm_ctx->cm_id->rem_ref(cm_ctx->cm_id);
			cm_ctx->cm_id = NULL;
		}
	}
}

static void event_connection_request(struct ibscif_cm *cm_ctx)
{
        struct iw_cm_event event;

        memset(&event, 0, sizeof(event));
        event.event = IW_CM_EVENT_CONNECT_REQUEST;
        event.local_addr = *(struct sockaddr_storage *) &cm_ctx->local_addr;
        event.remote_addr = *(struct sockaddr_storage *) &cm_ctx->remote_addr;
        event.private_data_len = cm_ctx->plen;
        event.private_data = cm_ctx->pdata;
        event.provider_data = cm_ctx;
	event.ird = 16;
	event.ord = 16;

        if (cm_ctx->listen) {
                cm_ctx->listen->cm_id->event_handler(cm_ctx->listen->cm_id,
						     &event);
		put_listen(cm_ctx->listen);
		cm_ctx->listen = NULL;
        }
}

static void event_connection_established( struct ibscif_cm *cm_ctx )
{
        struct iw_cm_event event;

        memset(&event, 0, sizeof(event));
        event.event = IW_CM_EVENT_ESTABLISHED;
	event.ird = 16;
	event.ord = 16;
        if (cm_ctx->cm_id) {
                cm_ctx->cm_id->event_handler(cm_ctx->cm_id, &event);
        }
}

void ibscif_cm_async_callback(void *cm_context)
{
        struct ibscif_cm *cm_ctx = cm_context;

        if (cm_ctx) {
                event_connection_close(cm_ctx);
                put_cm(cm_ctx);
        }
}

int ibscif_cm_connect(struct iw_cm_id *cm_id,
		      struct iw_cm_conn_param *conn_param)
{
	struct ibscif_cm *cm_ctx;
	struct sockaddr_in *local_addr, *remote_addr;
	int node_id, remote_node_id;
	int err = 0;

	cm_ctx = kzalloc(sizeof *cm_ctx, GFP_KERNEL);
	if (!cm_ctx) {
		printk(KERN_ALERT PFX "%s: cannot allocate cm_ctx\n", __func__);
		return -ENOMEM;
	}

	kref_init(&cm_ctx->kref); /* refcnt <- 1 */
	spin_lock_init(&cm_ctx->lock);

	local_addr = (struct sockaddr_in *) &cm_id->local_addr;
	remote_addr = (struct sockaddr_in *) &cm_id->remote_addr;
	node_id = sockaddr_in_to_node_id(*local_addr);
	remote_node_id = sockaddr_in_to_node_id(*remote_addr);
	if (node_id<0 || remote_node_id<0) {
		printk(KERN_ALERT PFX
			"%s: invalid address, local_addr=%8x, "
			"remote_addr=%8x, node_id=%d, remote_node_id=%d\n",
			__func__, local_addr->sin_addr.s_addr,
			remote_addr->sin_addr.s_addr,
			node_id, remote_node_id);
		err = -EINVAL;
		goto out_free;
	}

	cm_ctx->conn = ibscif_get_conn(node_id, remote_node_id, 0);
	if (!cm_ctx->conn) {
		printk(KERN_ALERT PFX "%s: failed to get connection %d-->%d\n",
			__func__, node_id, remote_node_id);
		err = -EINVAL;
		goto out_free;
	}

	cm_id->add_ref(cm_id);
	cm_id->provider_data = cm_ctx;

	cm_ctx->cm_id = cm_id;
	cm_ctx->node_id = node_id;
	cm_ctx->remote_node_id = remote_node_id;
	cm_ctx->local_addr = *local_addr;
	cm_ctx->remote_addr = *remote_addr;
	cm_ctx->qpn = conn_param->qpn;
	cm_ctx->plen = conn_param->private_data_len;
	if (cm_ctx->plen > IBSCIF_MAX_PDATA_SIZE) {
		printk(KERN_ALERT PFX
			"%s: plen (%d) exceeds the limit (%d), truncated.\n",
			__func__, cm_ctx->plen, IBSCIF_MAX_PDATA_SIZE);
		cm_ctx->plen = IBSCIF_MAX_PDATA_SIZE;
	}
	if (cm_ctx->plen)
		memcpy(cm_ctx->pdata, conn_param->private_data, cm_ctx->plen);

	err = ibscif_send_cm_req( cm_ctx );

	return err;

out_free:
	kfree(cm_ctx);
	return err;
}

int ibscif_cm_accept(struct iw_cm_id *cm_id,
		     struct iw_cm_conn_param *conn_param)
{
	struct ibscif_cm *cm_ctx = cm_id->provider_data;
	int err = 0;

	cm_id->add_ref(cm_id);
	cm_ctx->cm_id = cm_id;
	cm_ctx->qpn = conn_param->qpn;
	cm_ctx->plen = conn_param->private_data_len;
	if (cm_ctx->plen > IBSCIF_MAX_PDATA_SIZE) {
		printk(KERN_ALERT PFX
			"%s: plen (%d) exceeds the limit (%d), truncated.\n",
			__func__, cm_ctx->plen, IBSCIF_MAX_PDATA_SIZE);
		cm_ctx->plen = IBSCIF_MAX_PDATA_SIZE;
	}
	if (cm_ctx->plen)
		memcpy(cm_ctx->pdata, conn_param->private_data, cm_ctx->plen);

	err = connect_qp(cm_ctx);
	if (err) {
		printk(KERN_ALERT PFX
			"%s: failed to modify QP into connected state\n",
			__func__);
		goto err_out;
	}

	err = ibscif_send_cm_rep(cm_ctx);
	if (err) {
		printk(KERN_ALERT PFX "%s: failed to send REP\n", __func__);
		goto err_out;
	}

	return 0;

err_out:
	cm_id->rem_ref(cm_id);
	cm_ctx->cm_id = NULL;
	put_cm(cm_ctx);
	return err;
}

int ibscif_cm_reject(struct iw_cm_id *cm_id, const void *pdata, u8 pdata_len)
{
	struct ibscif_cm *cm_ctx = cm_id->provider_data;
	int err = 0;

	err = ibscif_send_cm_rej(cm_ctx, pdata, pdata_len);

	put_cm(cm_ctx);
	return err;
}

int ibscif_cm_create_listen(struct iw_cm_id *cm_id, int backlog)
{
	struct ibscif_listen *listen;
	struct sockaddr_in *local_addr;

	listen = kzalloc(sizeof *listen, GFP_KERNEL);
	if (!listen) {
		printk(KERN_ALERT PFX
			"%s: cannot allocate listen object\n", __func__);
		return -ENOMEM;
	}

	kref_init(&listen->kref);

	local_addr = (struct sockaddr_in *) &cm_id->local_addr;
	listen->cm_id = cm_id;
	listen->port = local_addr->sin_port;
	cm_id->provider_data = listen;
	cm_id->add_ref(cm_id);

	spin_lock_bh(&listen_list_lock);
	list_add(&listen->entry, &listen_list);
	spin_unlock_bh(&listen_list_lock);

	return 0;
}

int ibscif_cm_destroy_listen(struct iw_cm_id *cm_id)
{
	struct ibscif_listen *listen = cm_id->provider_data;

	spin_lock_bh(&listen_list_lock);
	list_del(&listen->entry);
	spin_unlock_bh(&listen_list_lock);
	cm_id->rem_ref(cm_id);
	put_listen(listen);

	return 0;
}

/* similar to ibscif_get_qp(), but differs in:
 * (1) use the "irqsave" version of the lock functions to avoid the
 *     kernel warnings about "local_bh_enable_ip";
 * (2) don't hold the reference on success;
 * (3) return NULL instead of error code on failure.
 */
struct ib_qp *ibscif_cm_get_qp(struct ib_device *ibdev, int qpn)
{
	struct ibscif_qp *qp;
	unsigned long flags;

	read_lock_irqsave(&wiremap_lock, flags);
	qp = idr_find(&wiremap, qpn);
	if (likely(qp) && unlikely(qp->magic != QP_MAGIC))
		qp = NULL;
	read_unlock_irqrestore(&wiremap_lock,flags);

	return qp ? &qp->ibqp : NULL;
}

void ibscif_cm_add_ref(struct ib_qp *ibqp)
{
	struct ibscif_qp *qp;

	if (likely(ibqp)) {
		qp = to_qp(ibqp);
		kref_get(&qp->ref);
	}
}

void ibscif_cm_rem_ref(struct ib_qp *ibqp)
{
	struct ibscif_qp *qp;

	if (likely(ibqp)) {
		qp = to_qp(ibqp);
		ibscif_put_qp(qp);
	}
}

int ibscif_process_cm_skb(struct sk_buff *skb, struct ibscif_conn *conn)
{
	union ibscif_pdu *pdu = (union ibscif_pdu *)skb->data;
	struct ibscif_cm *cm_ctx;
	struct ibscif_listen *listen;
	int cmd, qpn, status, plen, err, port;
	u64 req_ctx, rep_ctx;

	req_ctx	= __be64_to_cpu(pdu->cm.req_ctx);
	rep_ctx	= __be64_to_cpu(pdu->cm.rep_ctx);
	cmd	= __be32_to_cpu(pdu->cm.cmd);
	port	= __be32_to_cpu(pdu->cm.port);
	qpn	= __be32_to_cpu(pdu->cm.qpn);
	status	= __be32_to_cpu(pdu->cm.status);
	plen	= __be32_to_cpu(pdu->cm.plen);

	switch (cmd) {
	  case IBSCIF_CM_REQ:
		cm_ctx = kzalloc(sizeof *cm_ctx, GFP_KERNEL);
		if (!cm_ctx) {
			printk(KERN_ALERT PFX
				"%s: cannot allocate cm_ctx\n", __func__);
			return -ENOMEM;
		}
		kref_init(&cm_ctx->kref);
		spin_lock_init(&cm_ctx->lock);

		spin_lock_bh(&listen_list_lock);
		list_for_each_entry(listen, &listen_list, entry) {
			if (listen->port == port) {
				cm_ctx->listen = listen;
				get_listen(listen);
			}
		}
		spin_unlock_bh(&listen_list_lock);

		if (!cm_ctx->listen) {
			printk(KERN_ALERT PFX
				"%s: no matching listener for connection "
				"request, port=%d\n", __func__, port);
			put_cm(cm_ctx);
			/* TODO: send CM_REJ */
			return -EINVAL;
		}

		cm_ctx->cm_id = NULL;
		cm_ctx->node_id = conn->dev->node_id;
		cm_ctx->remote_node_id = conn->remote_node_id;
		cm_ctx->local_addr = node_id_to_sockaddr_in(cm_ctx->node_id);
		if (cm_ctx->listen)
			cm_ctx->local_addr.sin_port = cm_ctx->listen->port;
		cm_ctx->remote_addr =
			node_id_to_sockaddr_in(cm_ctx->remote_node_id);
		cm_ctx->remote_qpn = qpn;
		cm_ctx->plen = plen;
		if (cm_ctx->plen > IBSCIF_MAX_PDATA_SIZE) {
			printk(KERN_ALERT PFX
				"%s: plen (%d) exceeds the limit (%d), "
				"truncated.\n", __func__, cm_ctx->plen,
				IBSCIF_MAX_PDATA_SIZE);
			cm_ctx->plen = IBSCIF_MAX_PDATA_SIZE;
		}
		if (cm_ctx->plen)
			memcpy(cm_ctx->pdata, pdu->cm.pdata, cm_ctx->plen);

		cm_ctx->peer_context = req_ctx;
		cm_ctx->conn = conn;
		atomic_inc(&conn->refcnt);

		event_connection_request(cm_ctx);
		break;

	  case IBSCIF_CM_REP:
		cm_ctx = (struct ibscif_cm *)req_ctx;
		cm_ctx->plen = plen;
		memcpy(cm_ctx->pdata, pdu->cm.pdata, plen);
		cm_ctx->remote_qpn = qpn;
		cm_ctx->peer_context = rep_ctx;
		err = connect_qp(cm_ctx);
		if (!err)
			err = ibscif_send_cm_rtu(cm_ctx);
		if (err)
			printk(KERN_ALERT PFX
				"%s: failed to modify QP into connected "
				"state\n", __func__);
		event_connection_reply(cm_ctx, err);
		put_cm(cm_ctx);
		break;

	  case IBSCIF_CM_REJ:
		cm_ctx = (struct ibscif_cm *)req_ctx;
		cm_ctx->plen = plen;
		memcpy(cm_ctx->pdata, pdu->cm.pdata, plen);
		event_connection_reply(cm_ctx, status);
		put_cm(cm_ctx);
		break;

	  case IBSCIF_CM_RTU:
		cm_ctx = (struct ibscif_cm *)rep_ctx;
		event_connection_established(cm_ctx);
		put_cm(cm_ctx);
		break;

	  default:
		printk(KERN_ALERT PFX "%s: invalid CM cmd: %d\n",
			__func__, pdu->cm.cmd);
		break;
	}

	return 0;
}

