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

static struct ibscif_wr *
ibscif_alloc_wr(struct ibscif_wq *wq, int new_size, int bytes)
{
	if (new_size && (new_size != wq->size)) {
		struct ibscif_wr *new_wr = vzalloc(bytes);
		return new_wr ? new_wr : ERR_PTR(-ENOMEM);
	}
	return NULL;
}

static void ibscif_move_wr(struct ibscif_wq *wq, struct ibscif_wr *new_wr,
			   int new_size)
{
	int i;

	if (wq->size == new_size)
		return;

	for (i = 0; i < wq->depth; i++) {
		memcpy(&new_wr[i], &wq->wr[wq->head], wq->wr_size);
		wq->head = (wq->head + 1) % wq->size;
	}

	if (wq->wr) {
		vfree(wq->wr);
	}

	wq->wr   = new_wr;
	wq->head = 0;
	wq->tail = wq->depth;
	wq->size = new_size;
}

/* Caller must provide proper synchronization. */
static int ibscif_resize_qp(struct ibscif_qp *qp, int sq_size, int rq_size,
			    int iq_size)
{
	struct ibscif_wr *new_sq, *new_rq, *new_iq;
	int sq_bytes, rq_bytes, iq_bytes;
	int old_npages, new_npages, err;

	sq_bytes = PAGE_ALIGN(sq_size * qp->sq.wr_size);
	rq_bytes = PAGE_ALIGN(rq_size * qp->rq.wr_size);
	iq_bytes = PAGE_ALIGN(iq_size * qp->iq.wr_size);

	sq_size = sq_bytes / qp->sq.wr_size;
	rq_size = rq_bytes / qp->rq.wr_size;
	iq_size = iq_bytes / qp->iq.wr_size;

	if ((sq_size == qp->sq.size) &&
	    (rq_size == qp->rq.size) &&
	    (iq_size == qp->iq.size))
		return 0;

	if ((sq_size < qp->sq.depth) ||
	    (rq_size < qp->rq.depth) ||
	    (iq_size < qp->iq.depth))
		return -EINVAL;

	/* Calculate the number of new pages required for this allocation. */
	new_npages = (sq_bytes + rq_bytes + iq_bytes) >> PAGE_SHIFT;
	old_npages = (PAGE_ALIGN(qp->sq.size * qp->sq.wr_size) +
		      PAGE_ALIGN(qp->rq.size * qp->rq.wr_size) +
		      PAGE_ALIGN(qp->iq.size * qp->iq.wr_size)) >> PAGE_SHIFT;
	new_npages -= old_npages;

	if (new_npages > 0) {
		err = ibscif_reserve_quota(&new_npages);
		if (err)
			return err;
	}

	new_sq = ibscif_alloc_wr(&qp->sq, sq_size, sq_bytes);
	new_rq = ibscif_alloc_wr(&qp->rq, rq_size, rq_bytes);
	new_iq = ibscif_alloc_wr(&qp->iq, iq_size, iq_bytes);
	if (IS_ERR(new_sq) || IS_ERR(new_rq) || IS_ERR(new_iq))
		goto out;

	ibscif_move_wr(&qp->sq, new_sq, sq_size);
	ibscif_move_wr(&qp->rq, new_rq, rq_size);
	ibscif_move_wr(&qp->iq, new_iq, iq_size);

	if (new_npages < 0)
		ibscif_release_quota(-new_npages);

	return 0;
out:
	if (new_sq && !IS_ERR(new_sq))
		vfree(new_sq);
	if (new_rq && !IS_ERR(new_rq))
		vfree(new_rq);
	if (new_iq && !IS_ERR(new_iq))
		vfree(new_iq);

	return -ENOMEM;
}

static int ibscif_init_wqs(struct ibscif_qp *qp, struct ib_qp_init_attr *attr)
{
	spin_lock_init(&qp->sq.lock);
	spin_lock_init(&qp->rq.lock);
	spin_lock_init(&qp->iq.lock);

	qp->sq.qp = qp;
	qp->rq.qp = qp;
	qp->iq.qp = qp;

	qp->sq.wirestate = &qp->wire.sq;
	qp->iq.wirestate = &qp->wire.iq;

	qp->sq.max_sge = attr->cap.max_send_sge;
	qp->rq.max_sge = attr->cap.max_recv_sge;
	qp->iq.max_sge = 1;

	qp->sq.wr_size = sizeof *qp->sq.wr +
			 (sizeof *qp->sq.wr->ds_list * qp->sq.max_sge);
	qp->rq.wr_size = sizeof *qp->rq.wr +
			 (sizeof *qp->rq.wr->ds_list * qp->rq.max_sge);
	qp->iq.wr_size = sizeof *qp->iq.wr +
			 (sizeof *qp->iq.wr->ds_list * qp->iq.max_sge);

	return ibscif_resize_qp(qp, attr->cap.max_send_wr,
				attr->cap.max_recv_wr,
				(rma_threshold==0x7FFFFFFF) ?
					0 : attr->cap.max_send_wr);
}

static void ibscif_reset_tx_state(struct ibscif_tx_state *tx)
{
	tx->next_seq	       = 1;
	tx->last_ack_seq_recvd = 0;
	tx->next_msg_id	       = 0;
}

static void ibscif_reset_rx_state(struct ibscif_rx_state *rx)
{
	rx->last_in_seq	       = 0;
	rx->last_seq_acked     = 0;
	rx->defer_in_process   = 0;
}

static void ibscif_reset_wirestate(struct ibscif_wirestate *wirestate)
{
	ibscif_reset_tx_state(&wirestate->tx);
	ibscif_reset_rx_state(&wirestate->rx);
}

static void ibscif_reset_wire(struct ibscif_wire *wire)
{
	ibscif_reset_wirestate(&wire->sq);
	ibscif_reset_wirestate(&wire->iq);
}

static void ibscif_init_wire(struct ibscif_wire *wire)
{
	ibscif_reset_wire(wire);
}

static void ibscif_query_qp_cap(struct ibscif_qp *qp, struct ib_qp_cap *cap)
{
	memset(cap, 0, sizeof *cap);
	cap->max_send_wr  = qp->sq.size;
	cap->max_recv_wr  = qp->rq.size;
	cap->max_send_sge = qp->sq.max_sge;
	cap->max_recv_sge = qp->rq.max_sge;
}

struct ib_qp *ibscif_create_qp(struct ib_pd *ibpd,
			       struct ib_qp_init_attr *attr,
			       struct ib_udata *udata)
{
	struct ibscif_dev *dev = to_dev(ibpd->device);
	struct ibscif_qp *qp;
	int err;

	if ((attr->qp_type != IB_QPT_RC && attr->qp_type != IB_QPT_UD) ||
	    (attr->cap.max_send_wr  > MAX_QP_SIZE)    ||
	    (attr->cap.max_recv_wr  > MAX_QP_SIZE)    ||
	    (attr->cap.max_send_sge > MAX_SGES)	      ||
	    (attr->cap.max_recv_sge > MAX_SGES)	      ||
	    (attr->cap.max_send_wr && !attr->send_cq) ||
	    (attr->cap.max_recv_wr && !attr->recv_cq))
		return ERR_PTR(-EINVAL);

	if (!atomic_add_unless(&dev->qp_cnt, 1, MAX_QPS))
		return ERR_PTR(-EAGAIN);

	qp = kzalloc(sizeof *qp, GFP_KERNEL);
	if (!qp) {
		atomic_dec(&dev->qp_cnt);
		return ERR_PTR(-ENOMEM);
	}

	qp->local_node_id = dev->node_id;

	kref_init(&qp->ref);
	init_completion(&qp->done);
	mutex_init(&qp->modify_mutex);
	spin_lock_init(&qp->lock);
	ibscif_init_wire(&qp->wire);
	qp->sq_policy = attr->sq_sig_type;
	qp->dev	      = dev;
	qp->mtu	      = IBSCIF_MTU;
	qp->state     = QP_IDLE;

	err = ibscif_init_wqs(qp, attr);
	if (err)
		goto out;

	ibscif_query_qp_cap(qp, &attr->cap);

	err = ibscif_wiremap_add(qp, &qp->ibqp.qp_num);
	if (err)
		goto out;

	qp->magic = QP_MAGIC;

	ibscif_scheduler_add_qp(qp);
	qp->in_scheduler = 1;

	return &qp->ibqp;
out:
	ibscif_destroy_qp(&qp->ibqp);
	return ERR_PTR(err);
}

static inline enum ib_qp_state to_ib_qp_state(enum ibscif_qp_state state)
{
	switch (state) {
	case QP_IDLE:		return IB_QPS_INIT;
	case QP_CONNECTED:	return IB_QPS_RTS;
	case QP_DISCONNECT:	return IB_QPS_SQD;
	case QP_ERROR:		return IB_QPS_ERR;
	case QP_RESET:		return IB_QPS_RESET;
	default:		return -1;
	}
}

static inline enum ibscif_qp_state to_ibscif_qp_state(enum ib_qp_state state)
{
	switch (state) {
	case IB_QPS_INIT:	return QP_IDLE;
	case IB_QPS_RTS:	return QP_CONNECTED;
	case IB_QPS_SQD:	return QP_DISCONNECT;
	case IB_QPS_ERR:	return QP_ERROR;
	case IB_QPS_RESET:	return QP_RESET;
	case IB_QPS_RTR:	return QP_IGNORE;
	default:		return -1;
	}
}

/* Caller must provide proper synchronization. */
static void __ibscif_query_qp(struct ibscif_qp *qp, struct ib_qp_attr *attr,
			      struct ib_qp_init_attr *init_attr)
{
	struct ib_qp_cap cap;

	ibscif_query_qp_cap(qp, &cap);

	if (attr) {
		attr->qp_state		 = to_ib_qp_state(qp->state);
		attr->cur_qp_state	 = attr->qp_state;
		attr->port_num		 = 1;
		attr->path_mtu		 = qp->mtu;
		attr->dest_qp_num	 = qp->remote_qpn;
		attr->qp_access_flags	 = qp->access;
		attr->max_rd_atomic	 = qp->max_or;
		attr->max_dest_rd_atomic = qp->iq.size;
		attr->cap		 = cap;
	}

	if (init_attr) {
		init_attr->qp_type	 = qp->ibqp.qp_type;
		init_attr->sq_sig_type	 = qp->sq_policy;
		init_attr->cap		 = cap;
	}
}

int ibscif_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		    int attr_mask, struct ib_qp_init_attr *init_attr)
{
	struct ibscif_qp *qp = to_qp(ibqp);

	memset(attr, 0, sizeof *attr);
	memset(init_attr, 0, sizeof *init_attr);

	spin_lock_bh(&qp->lock);
	__ibscif_query_qp(qp, attr, init_attr);
	spin_unlock_bh(&qp->lock);

	return 0;
}

static int ibscif_flush_wq(struct ibscif_wq *wq, struct ibscif_cq *cq)
{
	struct ibscif_wr *wr;
	struct ibscif_wc *wc;
	int i, num_wr, err;

	/* Prevent divide by zero traps on wrap math. */
	if (!wq->size)
		return 0;

	spin_lock_bh(&wq->lock);
	for (i = (wq->head + wq->completions) % wq->size, num_wr = 0;
	     wq->depth && (wq->completions != wq->depth);
	     i = (i + 1) % wq->size, num_wr++) {

		wr = ibscif_get_wr(wq, i);

		ibscif_clear_ds_refs(wr->ds_list, wr->num_ds);

		if (!cq) {
			wq->completions++;
			continue;
		}

		err = ibscif_reserve_cqe(cq, &wc);
		if (err) {
			num_wr = err;
			break;
		}

		wc->ibwc.qp	  = &wq->qp->ibqp;
		wc->ibwc.src_qp	  = wq->qp->remote_qpn;
		wc->ibwc.wr_id	  = wr->id;
		wc->ibwc.opcode	  = is_rq(wq) ?
					IB_WC_RECV :
					to_ib_wc_opcode(wr->opcode);
		wc->ibwc.status	  = IB_WC_WR_FLUSH_ERR;
		wc->ibwc.ex.imm_data = 0;
		wc->ibwc.byte_len = 0;
		wc->ibwc.port_num = 1;

		wc->wq	 = wq;
		wc->reap = wq->reap + 1;
		wq->reap = 0;
		wq->completions++;

		ibscif_append_cqe(cq, wc, 0);
	}
	spin_unlock_bh(&wq->lock);

	if (num_wr && cq)
		ibscif_notify_cq(cq);

	return num_wr;
}

static void ibscif_flush_wqs(struct ibscif_qp *qp)
{
	int ret;

	ret = ibscif_flush_wq(&qp->sq, to_cq(qp->ibqp.send_cq));
	if (ret) /* A clean SQ flush should have done nothing. */
		qp->state = QP_ERROR;

	ret = ibscif_flush_wq(&qp->rq, to_cq(qp->ibqp.recv_cq));
	if (ret < 0)
		qp->state = QP_ERROR;

	ibscif_flush_wq(&qp->iq, NULL);
}

static void ibscif_reset_wq(struct ibscif_wq *wq, struct ibscif_cq *cq)
{
	ibscif_clear_cqes(cq, wq);

	wq->head	= 0;
	wq->tail	= 0;
	wq->depth	= 0;
	wq->reap	= 0;
	wq->next_wr	= 0;
	wq->next_msg_id	= 0;
	wq->completions = 0;
}

static void ibscif_reset_wqs(struct ibscif_qp *qp)
{
	ibscif_reset_wq(&qp->sq, to_cq(qp->ibqp.send_cq));
	ibscif_reset_wq(&qp->rq, to_cq(qp->ibqp.recv_cq));
	ibscif_reset_wq(&qp->iq, NULL);
}

static void ibscif_qp_event(struct ibscif_qp *qp, enum ib_event_type event)
{
	if (qp->ibqp.event_handler) {
		struct ib_event record;
		record.event	  = event;
		record.device	  = qp->ibqp.device;
		record.element.qp = &qp->ibqp;
		qp->ibqp.event_handler(&record, qp->ibqp.qp_context);
	}
}

/* Caller must provide proper synchronization. */
static void ibscif_qp_error(struct ibscif_qp *qp)
{
	if (qp->state == QP_ERROR)
		return;

	if (qp->state == QP_CONNECTED)
		ibscif_send_disconnect(qp, IBSCIF_REASON_DISCONNECT);

	qp->state = QP_ERROR;

	ibscif_flush_wqs(qp);

	ibscif_cm_async_callback(qp->cm_context);
	qp->cm_context = NULL;

	/* don't generate error event because transitioning to IB_QPS_ERR
	 * state is normal when a QP is disconnected
	 */
}

/* Caller must provide proper synchronization. */
static void ibscif_qp_reset(struct ibscif_qp *qp)
{
	if (qp->state == QP_RESET)
		return;

	if (qp->state == QP_CONNECTED)
		ibscif_send_disconnect(qp, IBSCIF_REASON_DISCONNECT);

	ibscif_reset_wqs(qp);
	ibscif_reset_wire(&qp->wire);

	ibscif_cm_async_callback(qp->cm_context);
	qp->cm_context = NULL;

	qp->state = QP_RESET;
}

/* Caller must provide proper synchronization. */
static void ibscif_qp_idle(struct ibscif_qp *qp)
{
	if (qp->state == QP_IDLE)
		return;

	ibscif_reset_wqs(qp);
	ibscif_reset_wire(&qp->wire);

	qp->state = QP_IDLE;
}

/* Caller must provide proper synchronization. */
static void ibscif_qp_connect(struct ibscif_qp *qp,
			      enum ibscif_qp_state cur_state)
{
	if (cur_state == QP_CONNECTED)
		return;

	qp->loopback = (qp->ibqp.qp_type != IB_QPT_UD) &&
		       !scif_loopback &&
		       (qp->local_node_id == qp->remote_node_id);
	qp->conn = NULL;

	qp->state = QP_CONNECTED;
}

/* Caller must provide proper synchronization. */
static void ibscif_qp_local_disconnect(struct ibscif_qp *qp,
				       enum ibscif_reason reason)
{
	if (qp->state != QP_CONNECTED)
		return;

	if (reason != IBSCIF_REASON_DISCONNECT)
		printk(KERN_NOTICE PFX
			"QP %u sending abnormal disconnect %d\n",
			qp->ibqp.qp_num, reason);

	qp->state = QP_DISCONNECT;
	ibscif_send_disconnect(qp, reason);

	ibscif_flush_wqs(qp);

	ibscif_cm_async_callback(qp->cm_context);
	qp->cm_context = NULL;

	if (reason != IBSCIF_REASON_DISCONNECT) {
		qp->state = QP_ERROR;
		ibscif_qp_event(qp, IB_EVENT_QP_FATAL);
	} else
		ibscif_qp_idle(qp);
}

void ibscif_qp_internal_disconnect(struct ibscif_qp *qp,
				   enum ibscif_reason reason)
{
	spin_lock_bh(&qp->lock);
	ibscif_qp_local_disconnect(qp, reason);
	spin_unlock_bh(&qp->lock);
}

void ibscif_qp_remote_disconnect(struct ibscif_qp *qp,
				 enum ibscif_reason reason)
{
	if (reason != IBSCIF_REASON_DISCONNECT)
		printk(KERN_NOTICE PFX
			"QP %u received abnormal disconnect %d\n",
			qp->ibqp.qp_num, reason);

	if (qp->loopback) {
		/*
		 * Prevent simultaneous loopback QP disconnect deadlocks.
		 * This is no worse than dropping a disconnect packet.
		 */
		if (!spin_trylock_bh(&qp->lock))
			return;
	} else
		spin_lock_bh(&qp->lock);

	if (qp->state != QP_CONNECTED) {
		spin_unlock_bh(&qp->lock);
		return;
	}

	ibscif_flush_wqs(qp);

	ibscif_cm_async_callback(qp->cm_context);
	qp->cm_context = NULL;

	if (reason != IBSCIF_REASON_DISCONNECT) {
		qp->state = QP_ERROR;
		ibscif_qp_event(qp, IB_EVENT_QP_FATAL);
	} else
		qp->state = QP_IDLE;

	spin_unlock_bh(&qp->lock);
}

#define	MODIFY_ALLOWED					1
#define	MODIFY_INVALID					0
#define	VALID_TRANSITION(next_state, modify_allowed)	{ 1, modify_allowed },
#define	INVAL_TRANSITION(next_state)			{ 0, MODIFY_INVALID },
#define	START_STATE(current_state)			{
#define	CEASE_STATE(current_state)			},

static const struct {

	int valid;
	int modify_allowed;

} qp_transition[NR_QP_STATES][NR_QP_STATES] = {

	START_STATE(QP_IDLE)
		VALID_TRANSITION( QP_IDLE,	 MODIFY_ALLOWED	)
		VALID_TRANSITION( QP_CONNECTED,	 MODIFY_ALLOWED	)
		INVAL_TRANSITION( QP_DISCONNECT			)
		VALID_TRANSITION( QP_ERROR,	 MODIFY_INVALID	)
		VALID_TRANSITION( QP_RESET,	 MODIFY_INVALID	)
		VALID_TRANSITION( QP_IGNORE,	 MODIFY_ALLOWED	)
	CEASE_STATE(QP_IDLE)

	START_STATE(QP_CONNECTED)
		INVAL_TRANSITION( QP_IDLE			)
		VALID_TRANSITION( QP_CONNECTED,	 MODIFY_INVALID	)
		VALID_TRANSITION( QP_DISCONNECT, MODIFY_INVALID	)
		VALID_TRANSITION( QP_ERROR,	 MODIFY_INVALID	)
		VALID_TRANSITION( QP_RESET,	 MODIFY_INVALID	)
		VALID_TRANSITION( QP_IGNORE,	 MODIFY_ALLOWED	)
	CEASE_STATE(QP_CONNECTED)

	START_STATE(QP_DISCONNECT) /* Automatic transition to IDLE */
		INVAL_TRANSITION( QP_IDLE			)
		INVAL_TRANSITION( QP_CONNECTED			)
		INVAL_TRANSITION( QP_DISCONNECT			)
		INVAL_TRANSITION( QP_ERROR			)
		INVAL_TRANSITION( QP_RESET			)
		INVAL_TRANSITION( QP_IGNORE			)
	CEASE_STATE(QP_DISCONNECT)

	START_STATE(QP_ERROR)
		VALID_TRANSITION( QP_IDLE,	 MODIFY_INVALID	)
		INVAL_TRANSITION( QP_CONNECTED			)
		INVAL_TRANSITION( QP_DISCONNECT			)
		VALID_TRANSITION( QP_ERROR,	 MODIFY_INVALID	)
		VALID_TRANSITION( QP_RESET,	 MODIFY_INVALID	)
		VALID_TRANSITION( QP_IGNORE,	 MODIFY_ALLOWED	)
	CEASE_STATE(QP_ERROR)

	START_STATE(QP_RESET)
		VALID_TRANSITION( QP_IDLE,	 MODIFY_ALLOWED	)
		INVAL_TRANSITION( QP_CONNECTED			)
		INVAL_TRANSITION( QP_DISCONNECT			)
		VALID_TRANSITION( QP_ERROR,	 MODIFY_INVALID	)
		VALID_TRANSITION( QP_RESET,	 MODIFY_INVALID	)
		VALID_TRANSITION( QP_IGNORE,	 MODIFY_ALLOWED	)
	CEASE_STATE(QP_RESET)
};

int ibscif_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		     int attr_mask, struct ib_udata *udata)
{
	struct ibscif_qp *qp = to_qp(ibqp);
	enum ibscif_qp_state cur_state, new_state;
	int sq_size, rq_size, max_or, max_ir;
	int err = -EINVAL;

	/*
	 * Mutex prevents simultaneous user-mode QP modifies.
	 */
	mutex_lock(&qp->modify_mutex);

	cur_state = qp->state;

	if ((attr_mask & IB_QP_CUR_STATE) &&
	    (to_ibscif_qp_state(attr->cur_qp_state) != cur_state))
		goto out;
	if ((attr_mask & IB_QP_PORT) &&
	    (attr->port_num == 0 || attr->port_num > 1))
		goto out;

	/* Validate any state transition. */
	if (attr_mask & IB_QP_STATE) {
		new_state = to_ibscif_qp_state(attr->qp_state);
		if (new_state < 0 || new_state >= NR_QP_STATES)
			goto out;

		if (!qp_transition[cur_state][new_state].valid)
			goto out;
	} else
		new_state = cur_state;

	/* Validate any attribute modify request. */
	if (attr_mask & (IB_QP_AV		  |
			 IB_QP_CAP		  |
			 IB_QP_DEST_QPN		  |
			 IB_QP_ACCESS_FLAGS	  |
			 IB_QP_MAX_QP_RD_ATOMIC	  |
			 IB_QP_MAX_DEST_RD_ATOMIC)) {

		if (!qp_transition[cur_state][new_state].modify_allowed)
			goto out;

		if ((attr_mask & IB_QP_AV) &&
		    (attr->ah_attr.ah_flags & IB_AH_GRH) && check_grh) {
			int remote_node_id =
				IBSCIF_LID_TO_NODE_ID(attr->ah_attr.dlid);
			struct ibscif_conn *conn;
			union ib_gid *dgid;

			if (verbose) {
				printk(KERN_INFO PFX
					"%s: %d-->%d, DGID=%llx:%llx\n",
					__func__, qp->local_node_id,
					remote_node_id,
					__be64_to_cpu(attr->ah_attr.grh.dgid.
						      global.subnet_prefix),
					__be64_to_cpu(attr->ah_attr.grh.dgid.
						      global.interface_id));
			}

			if (remote_node_id == qp->local_node_id) {
				dgid = &qp->dev->gid;
			}
			else {
				spin_lock(&qp->lock);
				conn = ibscif_get_conn(qp->local_node_id,
						       remote_node_id, 0);
				spin_unlock(&qp->lock);
				if (!conn) {
					if (verbose)
						printk(KERN_INFO PFX
							"%s: failed to make "
							"SCIF connection "
							"%d-->%d.\n",
							__func__,
							qp->local_node_id,
							remote_node_id);
					goto out;
				}
				dgid = &conn->remote_gid;
				ibscif_put_conn(conn);
			}

			if (verbose)
				printk(KERN_INFO PFX
					"%s: local GID[%d]=%llx:%llx\n",
					__func__, remote_node_id,
					__be64_to_cpu(
						dgid->global.subnet_prefix),
					__be64_to_cpu(
						dgid->global.interface_id));

			if (memcmp(dgid, &attr->ah_attr.grh.dgid,
				   sizeof(*dgid))) {
				if (verbose)
					printk(KERN_INFO PFX
						"%s: connecting to DGID "
						"outside the box is "
						"unsupported.\n",
						__func__);
				goto out;
			}
		}

		if (attr_mask & IB_QP_CAP) {
			sq_size = attr->cap.max_send_wr;
			rq_size = attr->cap.max_recv_wr;
			if ((sq_size > MAX_QP_SIZE) || (rq_size > MAX_QP_SIZE))
				goto out;
		} else {
			sq_size = qp->sq.size;
			rq_size = qp->rq.size;
		}
		if ((sq_size && !qp->ibqp.send_cq) ||
		    (rq_size && !qp->ibqp.recv_cq))
			goto out;

		max_or = (attr_mask & IB_QP_MAX_QP_RD_ATOMIC) ?
			  attr->max_rd_atomic : qp->max_or;
		max_ir = (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC) ?
			  attr->max_dest_rd_atomic : qp->iq.size;

		if (rma_threshold < 0x7FFFFFFF && max_ir > MAX_IR &&
		    max_ir >= qp->sq.size)
			max_ir -= qp->sq.size;

		if ((max_or > MAX_OR) || (max_ir > MAX_IR))
			goto out;

		/* Validation successful; resize the QP as needed. */
		err = ibscif_resize_qp(qp, sq_size, rq_size,
				       max_ir +
					   (rma_threshold == 0x7FFFFFFFFL ?
						0 : sq_size));
		if (err)
			goto out;

		/* No failure paths below the QP resize. */

		qp->max_or = max_or;

		if (attr_mask & IB_QP_ACCESS_FLAGS)
			qp->access = attr->qp_access_flags;

		if (attr_mask & IB_QP_DEST_QPN)
			qp->remote_qpn = attr->dest_qp_num;

		if (attr_mask & IB_QP_AV)
			qp->remote_node_id =
				IBSCIF_LID_TO_NODE_ID(attr->ah_attr.dlid);
	}

	err = 0;
	if (attr_mask & IB_QP_STATE) {

		/* Perform state change processing. */
		spin_lock_bh(&qp->lock);
		switch (new_state) {
		case QP_IDLE:
			ibscif_qp_idle(qp);
			break;
		case QP_CONNECTED:
			ibscif_qp_connect(qp, cur_state);
			break;
		case QP_DISCONNECT:
			ibscif_qp_local_disconnect(qp, IBSCIF_REASON_DISCONNECT);
			break;
		case QP_ERROR:
			ibscif_qp_error(qp);
			break;
		case QP_RESET:
			ibscif_qp_reset(qp);
			break;
		default:
			break;
		}
		spin_unlock_bh(&qp->lock);

		/* scif_connect() can not be called with spin_lock_bh() held */
		if (ibqp->qp_type != IB_QPT_UD &&
		    new_state == QP_CONNECTED &&
		    !qp->loopback) {
			int flag = (qp->ibqp.qp_num > qp->remote_qpn);
			spin_lock(&qp->lock);
			qp->conn = ibscif_get_conn(qp->local_node_id,
						   qp->remote_node_id, flag);
			spin_unlock(&qp->lock);
		}
	}

	__ibscif_query_qp(qp, attr, NULL);
out:
	mutex_unlock(&qp->modify_mutex);
	return err;
}

void ibscif_complete_qp(struct kref *ref)
{
	struct ibscif_qp *qp = container_of(ref, struct ibscif_qp, ref);
	complete(&qp->done);
}

int ibscif_destroy_qp(struct ib_qp *ibqp)
{
	struct ibscif_qp *qp = to_qp(ibqp);
	struct ibscif_dev *dev = qp->dev;
	int i, j;
	struct ibscif_conn *conn[IBSCIF_MAX_DEVICES];

	if (qp->cm_context) {
		ibscif_cm_async_callback(qp->cm_context);
		qp->cm_context = NULL;
	}

	if (ibqp->qp_num)
		ibscif_wiremap_del(ibqp->qp_num);

	if (qp->in_scheduler)
		ibscif_scheduler_remove_qp(qp);

	spin_lock_bh(&qp->lock);
	if (qp->state == QP_CONNECTED)
		ibscif_send_disconnect(qp, IBSCIF_REASON_DISCONNECT);
	spin_unlock_bh(&qp->lock);

	ibscif_put_qp(qp);
	wait_for_completion(&qp->done);

	ibscif_flush_wqs(qp);
	ibscif_reset_wqs(qp);
	ibscif_reset_wire(&qp->wire);

	if (qp->sq.wr)
		vfree(qp->sq.wr);
	if (qp->rq.wr)
		vfree(qp->rq.wr);
	if (qp->iq.wr)
		vfree(qp->iq.wr);

	ibscif_release_quota((PAGE_ALIGN(qp->sq.size * qp->sq.wr_size) +
			      PAGE_ALIGN(qp->rq.size * qp->rq.wr_size) +
			      PAGE_ALIGN(qp->iq.size * qp->iq.wr_size)) >>
				PAGE_SHIFT);

	atomic_dec(&dev->qp_cnt);

	ibscif_put_conn(qp->conn);

	if (qp->ibqp.qp_type == IB_QPT_UD) {
		spin_lock_bh(&qp->lock);
		for (i=0, j=0; i<IBSCIF_MAX_DEVICES; i++) {
			if (qp->ud_conn[i]) {
				conn[j++] = qp->ud_conn[i];
				qp->ud_conn[i] = NULL;
			}
		}
		spin_unlock_bh(&qp->lock);

		/* ibscif_put_conn() may call scif_unregister(),
		 * and thus should not hold a lock
		 */
		for (i=0; i<j; i++)
			ibscif_put_conn(conn[i]);
	}

	kfree(qp);
	return 0;
}

void ibscif_qp_add_ud_conn(struct ibscif_qp *qp, struct ibscif_conn *conn)
{
	int i;

	if (!qp || !conn)
		return;

	if (qp->ibqp.qp_type != IB_QPT_UD)
		return;

	spin_lock_bh(&qp->lock);

	for (i=0; i<IBSCIF_MAX_DEVICES; i++) {
		if (qp->ud_conn[i] == conn)
			goto done;
	}

	for (i=0; i<IBSCIF_MAX_DEVICES; i++) {
		if (qp->ud_conn[i] == NULL) {
			atomic_inc(&conn->refcnt);
			qp->ud_conn[i] = conn;
			break;
		}
	}
done:
	spin_unlock_bh(&qp->lock);
}

