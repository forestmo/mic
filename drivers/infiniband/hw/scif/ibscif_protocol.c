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
#include <linux/sched.h>

/* dev/wr/qp backpointers overlayed in skb cb[] */
struct ibscif_skb_cb {
	struct ibscif_dev	*dev;
	struct ibscif_wr	*wr;
	scif_epd_t		scif_ep;
	struct ibscif_qp	*qp;	/* for UD only */
};

#define SET_SKB_DEV(skb,dev0)	((struct ibscif_skb_cb *)&skb->cb)->dev=dev0
#define SET_SKB_WR(skb,wr0)	((struct ibscif_skb_cb *)&skb->cb)->wr=wr0
#define SET_SKB_EP(skb,ep0)	((struct ibscif_skb_cb *)&skb->cb)->scif_ep=ep0
#define SET_SKB_QP(skb,qp0)	((struct ibscif_skb_cb *)&skb->cb)->qp=qp0

#define GET_SKB_DEV(skb)	((struct ibscif_skb_cb *)&skb->cb)->dev
#define GET_SKB_WR(skb)		((struct ibscif_skb_cb *)&skb->cb)->wr
#define GET_SKB_EP(skb)		((struct ibscif_skb_cb *)&skb->cb)->scif_ep
#define GET_SKB_QP(skb)		((struct ibscif_skb_cb *)&skb->cb)->qp

#define SET_PAGE(x,y) __skb_frag_set_page(x, y)
#define GET_PAGE(x) __skb_frag_ref(x)

static void ibscif_skb_destructor(struct sk_buff *skb)
{
	struct ibscif_dev *dev = GET_SKB_DEV(skb);

	if (atomic_inc_return(&dev->available) == 1)
		; /* Could invoke the scheduler here. */

	module_put(THIS_MODULE);
}

static struct sk_buff *ibscif_alloc_tx_skb(struct ibscif_dev *dev,
					   int hdr_size, int payload_size)
{
	struct sk_buff *skb;

	skb = dev_alloc_skb(hdr_size);
	if (unlikely(!skb))
		return NULL;

	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);

	skb->protocol  = __cpu_to_be16(IBSCIF_PACKET_TYPE);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->priority  = TC_PRIO_CONTROL; /* highest defined priority */
	skb->dev       = (void *) dev;
	skb->len       = hdr_size + payload_size;
	skb->data_len  = payload_size;
	skb->tail     += hdr_size;

	return skb;
}

static struct	sk_buff_head xmit_queue;
static void	ibscif_xmit_work_handler( struct work_struct *context );
static DECLARE_WORK(ibscif_xmit_work, ibscif_xmit_work_handler);
static atomic_t	xmit_busy = ATOMIC_INIT(0);

static void ibscif_xmit_work_handler( struct work_struct *context )
{
	struct sk_buff *skb;
	scif_epd_t scif_ep;
	int num_frags;
	skb_frag_t *frag;
	void *vaddr;
	int ret;
	int hdr_size;
	int i;
	struct ibscif_qp *qp;

again:
	while ((skb = skb_dequeue(&xmit_queue))) {
		scif_ep = GET_SKB_EP(skb);
		if (!scif_ep) {
			printk(KERN_ALERT PFX
				"%s: NULL scif_ep, skb=%p\n", __func__, skb);
			goto next;
		}

		hdr_size = skb->len - skb->data_len;
		for (i=0; i<hdr_size; ) {
			ret = scif_send(scif_ep, skb->data+i, hdr_size-i,
					 blocking_send ? SCIF_SEND_BLOCK : 0);
			if (ret < 0) {
				printk(KERN_ALERT PFX
					"%s: fail to send header, "
					"hdr_size=%d, ret=%d\n",
					__func__, hdr_size, ret);
				goto next;
			}
			i += ret;
		}

		num_frags = skb_shinfo(skb)->nr_frags;
		frag = skb_shinfo(skb)->frags;
		while (num_frags--) {
			vaddr = kmap(skb_frag_page(frag));
			for (i=0; i<frag->size; ) {
				ret = scif_send(scif_ep,
						vaddr + frag->page_offset + i,
						frag->size - i,
						blocking_send ?
							SCIF_SEND_BLOCK : 0);
				if (ret < 0) {
					printk(KERN_ALERT PFX
						"%s: scif_send returns %d, "
						"frag_size=%d\n",
						__func__, ret, frag->size);
					break;
				}
				i += ret;
			}
			kunmap(skb_frag_page(frag));
			frag++;
		}
next:
		qp = GET_SKB_QP(skb);
		if (qp && qp->ibqp.qp_type == IB_QPT_UD) {
			struct ibscif_full_frame *pdu =
				(struct ibscif_full_frame*)skb->data;
			u16 opcode = pdu->ibscif.hdr.opcode;
			if (ibscif_pdu_is_last(opcode)) {
				struct ibscif_wr *wr = GET_SKB_WR(skb);
				ibscif_clear_ds_refs(wr->ds_list, wr->num_ds);
				wr->state = WR_COMPLETED;
				ibscif_process_sq_completions(GET_SKB_QP(skb));
			}
			ibscif_put_qp(qp);
		}
		kfree_skb(skb);
	}

	if (!skb_queue_empty(&xmit_queue))
		goto again;

	atomic_set(&xmit_busy, 0);
}

static void ibscif_dev_queue_xmit(struct sk_buff *skb)
{
	struct ibscif_dev *dev=NULL;
	int len = 0;

	if (skb) {
		dev = GET_SKB_DEV(skb);
		len = skb->len;
		skb_queue_tail(&xmit_queue, skb);
	}

	/* only one instance can be enqueued, otherwise there is race
	 * condition between scif_send() calls. notice that the current
	 * running worker may miss the newly added item, but it will be
	 * picked up in the poll_thread */

	if (!atomic_xchg(&xmit_busy, 1))
		schedule_work(&ibscif_xmit_work);

	if (likely(dev)) {
		DEV_STAT(dev, packets_sent++);
		DEV_STAT(dev, bytes_sent += len);
	}
}

static int ibscif_create_hdr(struct ibscif_qp *qp, struct ibscif_wr *wr,
			     struct sk_buff *skb, u32 seq_num,
			     u32 wr_len_remaining, int force)
{
	struct ibscif_full_frame *pdu = (struct ibscif_full_frame*)skb->data;
	u64 offset;
	u32 sq_seq, iq_seq;
	u16 opcode;
	int i;

	sq_seq = qp->wire.sq.rx.last_in_seq;
	iq_seq = qp->wire.iq.rx.last_in_seq;
	qp->wire.sq.rx.last_seq_acked = sq_seq;
	qp->wire.iq.rx.last_seq_acked = iq_seq;

	pdu->ibscif.hdr.length	 = skb->data_len;
	if (qp->ibqp.qp_type == IB_QPT_UD) {
		pdu->ibscif.hdr.dst_qp	 = wr->ud.remote_qpn;
	}
	else {
		pdu->ibscif.hdr.dst_qp	 = qp->remote_qpn;
	}
	pdu->ibscif.hdr.src_qp	 = qp->ibqp.qp_num;
	pdu->ibscif.hdr.seq_num	 = seq_num;
	pdu->ibscif.hdr.sq_ack_num = sq_seq;
	pdu->ibscif.hdr.iq_ack_num = iq_seq;

	switch (wr->opcode) {
	case WR_UD:
		opcode = ibscif_op_ud;
		if (skb->data_len == wr_len_remaining) {
			opcode = ibscif_pdu_set_last(opcode);
			if (wr->flags & IB_SEND_SIGNALED)
				force = 1;
			if (wr->flags & IB_SEND_SOLICITED)
				opcode = ibscif_pdu_set_se(opcode);
		}
		pdu->ibscif.ud.msg_length = wr->length;
		pdu->ibscif.ud.msg_offset = wr->length - wr_len_remaining;
		memset(&pdu->ibscif.ud.grh, 0, 40);
		break;

	case WR_SEND:
	case WR_SEND_WITH_IMM:
		opcode = ibscif_op_send;
		if (skb->data_len == wr_len_remaining ||
		    opcode == ibscif_op_send_rma) {
			opcode = ibscif_pdu_set_last(opcode);
			if (wr->flags & IB_SEND_SIGNALED)
				force = 1;
			if (wr->opcode == WR_SEND_WITH_IMM) {
				opcode = ibscif_pdu_set_immed(opcode);
				pdu->ibscif.send.immed_data =
					wr->send.immediate_data;
			} else pdu->ibscif.send.immed_data = 0;
			if (wr->flags & IB_SEND_SOLICITED)
				opcode = ibscif_pdu_set_se(opcode);
		}
		pdu->ibscif.send.msg_id	= wr->msg_id;
		pdu->ibscif.send.msg_length = wr->length;
		pdu->ibscif.send.msg_offset = wr->length - wr_len_remaining;
		if (wr->use_rma) {
			opcode = ibscif_op_send_rma;
			pdu->ibscif.send.rma_id = wr->rma_id;
			pdu->ibscif.send.num_rma_addrs = wr->num_ds;
			for (i=0; i<wr->num_ds; i++) {
				offset = wr->ds_list[i].current_mreg->offset +
					 wr->ds_list[i].offset;
				pdu->ibscif.send.rma_addrs[i].offset = offset;
				pdu->ibscif.send.rma_addrs[i].length =
					wr->ds_list[i].length;
			}
		}
		break;

	case WR_RDMA_READ:
		opcode = ibscif_op_read;
		pdu->ibscif.read_req.rdma_id = wr->msg_id;
		pdu->ibscif.read_req.rdma_key = wr->read.rkey;
		pdu->ibscif.read_req.rdma_length = wr->read.remote_length;
		pdu->ibscif.read_req.rdma_address = wr->read.remote_address;
		if (wr->use_rma) {
			opcode = ibscif_op_read_rma;
			pdu->ibscif.read_req.num_rma_addrs = wr->num_ds;
			for (i=0; i<wr->num_ds; i++) {
				offset = wr->ds_list[i].current_mreg->offset +
					 wr->ds_list[i].offset;
				pdu->ibscif.read_req.rma_addrs[i].offset =
					offset;
				pdu->ibscif.read_req.rma_addrs[i].length =
					wr->ds_list[i].length;
			}
		}
		break;

	case WR_RDMA_WRITE:
	case WR_RDMA_WRITE_WITH_IMM:
		opcode = ibscif_op_write;
		if ((enum ib_wr_opcode)wr->opcode == IB_WR_RDMA_WRITE_WITH_IMM){
			opcode = ibscif_pdu_set_immed(opcode);
			pdu->ibscif.write.immed_data =
				wr->write.immediate_data;
			if (wr->flags & IB_SEND_SOLICITED)
				opcode = ibscif_pdu_set_se(opcode);
		} else pdu->ibscif.write.immed_data = 0;
		if (skb->data_len == wr_len_remaining ||
		    opcode == ibscif_op_write_rma) {
			opcode = ibscif_pdu_set_last(opcode);
			if (wr->flags & IB_SEND_SIGNALED)
				force = 1;
		}
		pdu->ibscif.write.msg_id = wr->msg_id;
		pdu->ibscif.write.rdma_key = wr->write.rkey;
		pdu->ibscif.write.rdma_address = wr->write.remote_address +
						(wr->length - wr_len_remaining);
		if (wr->use_rma) {
			opcode = ibscif_op_write_rma;
			if (wr->opcode == WR_RDMA_WRITE_WITH_IMM)
				opcode = ibscif_pdu_set_immed(opcode);
			pdu->ibscif.write.rma_id = wr->rma_id;
			pdu->ibscif.write.rma_length = wr->length;
			pdu->ibscif.write.num_rma_addrs = wr->num_ds;
			for (i=0; i<wr->num_ds; i++) {
				offset = wr->ds_list[i].current_mreg->offset +
					 wr->ds_list[i].offset;
				pdu->ibscif.write.rma_addrs[i].offset = offset;
				pdu->ibscif.write.rma_addrs[i].length =
					wr->ds_list[i].length;
			}
		}
		break;

	case WR_ATOMIC_CMP_AND_SWP:
		opcode = ibscif_pdu_set_last(ibscif_op_comp_swap);
		pdu->ibscif.comp_swap.atomic_id = wr->msg_id;
		pdu->ibscif.comp_swap.atomic_key = wr->cmp_swp.rkey;
		pdu->ibscif.comp_swap.comp_data = wr->cmp_swp.cmp_operand;
		pdu->ibscif.comp_swap.swap_data = wr->cmp_swp.swp_operand;
		pdu->ibscif.comp_swap.atomic_address =
			wr->cmp_swp.remote_address;
		break;

	case WR_ATOMIC_FETCH_AND_ADD:
		opcode = ibscif_pdu_set_last(ibscif_op_fetch_add);
		pdu->ibscif.fetch_add.atomic_id = wr->msg_id;
		pdu->ibscif.fetch_add.atomic_key = wr->fetch_add.rkey;
		pdu->ibscif.fetch_add.add_data = wr->fetch_add.add_operand;
		pdu->ibscif.fetch_add.atomic_address =
			wr->fetch_add.remote_address;
		break;

	case WR_RDMA_READ_RSP:
		opcode = ibscif_op_read_rsp;
		if (skb->data_len == wr_len_remaining)
			opcode = ibscif_pdu_set_last(opcode);
		pdu->ibscif.read_rsp.rdma_id = wr->msg_id;
		pdu->ibscif.read_rsp.rdma_offset = wr->length -
						   wr_len_remaining;
		break;

	case WR_ATOMIC_RSP:
		opcode = ibscif_pdu_set_last(wr->atomic_rsp.opcode);
		pdu->ibscif.atomic_rsp.atomic_id = wr->msg_id;
		pdu->ibscif.atomic_rsp.orig_data = wr->atomic_rsp.orig_data;
		break;

	case WR_RMA_RSP:
		opcode = ibscif_op_rma_rsp;
		pdu->ibscif.rma_rsp.rma_id = wr->msg_id;
		pdu->ibscif.rma_rsp.xfer_length	= wr->rma_rsp.xfer_length;
		pdu->ibscif.rma_rsp.error = wr->rma_rsp.error;
		break;
	default:
		printk(KERN_ERR PFX "%s() invalid opcode %d\n",
			__func__, wr->opcode);
		return 1;
	}

	if (force)
		opcode = ibscif_pdu_set_force_ack(opcode);

	pdu->ibscif.hdr.opcode = opcode;

	return 0;
}

static struct sk_buff* ibscif_alloc_pdu(struct ibscif_dev *dev,
					struct ibscif_qp *qp,
					struct ibscif_wr *wr,
					int hdr_size, u32 seq_num,
					u32 payload_size, u32 len_remaining,
					int force)
{
	struct sk_buff *skb;
	struct ibscif_full_frame *pdu;

	if (unlikely(!qp->conn && qp->ibqp.qp_type != IB_QPT_UD)) {
		printk(KERN_ALERT PFX "%s: ERROR: qp->conn == NULL\n",
			__func__);
		return NULL;
	}

	if (!atomic_add_unless(&dev->available, -1, 0)) {
		printk(KERN_NOTICE PFX
			"%s: %s throttled by available tx buffer limit\n",
			__func__, dev->ibdev.name);
		DEV_STAT(dev, unavailable++);
		return NULL;
	}

	/* Get an skb for this protocol packet. */
	skb = ibscif_alloc_tx_skb(dev, hdr_size, payload_size);
	if (unlikely(!skb))
		goto bail;

	/* Hold a reference on the module until skb->destructor is called. */
	__module_get(THIS_MODULE);
	skb->destructor = ibscif_skb_destructor;

	SET_SKB_DEV(skb, dev);
	SET_SKB_WR(skb, wr);

	if (qp->ibqp.qp_type == IB_QPT_UD) {
		struct ibscif_conn *conn;
		int flag = qp->ibqp.qp_num > wr->ud.remote_qpn;
		conn = ibscif_get_conn(qp->local_node_id,
				       wr->ud.remote_node_id, flag);
		if (unlikely(!conn)) {
			kfree_skb(skb);
			goto bail;
		}

		ibscif_qp_add_ud_conn(qp, conn);
		ibscif_put_conn(conn);
		SET_SKB_EP(skb, conn->ep);
		SET_SKB_QP(skb, qp);

		/* Reference UD QPs until the wr is transmitted by
		 * ibscif_xmit_work_handler
		 */
		kref_get(&qp->ref);
	}
	else {
		SET_SKB_EP(skb, qp->conn->ep);
	}

	/* Construct the header and copy it to the skb. */
	if (unlikely(ibscif_create_hdr(qp, wr, skb, seq_num, len_remaining,
				       force))) {
		kfree_skb(skb);
		goto bail;
	}

	pdu = (struct ibscif_full_frame *)skb->data;
	pdu->ibscif.hdr.hdr_size = hdr_size;

	return skb;
bail:
	atomic_inc(&dev->available);
	return NULL;
}

static int ibscif_send_null_pdu(struct ibscif_dev *dev, struct ibscif_qp *qp,
				struct ibscif_wr *wr, u32 hdr_size)
{
	struct sk_buff *skb;

	/* Allocate an initialized skb with a PDU header. */
	skb = ibscif_alloc_pdu(dev, qp, wr, hdr_size,
			       wr->sar.seg.starting_seq, 0, 0, 0);
	if (unlikely(!skb))
		return 0;

	ibscif_dev_queue_xmit(skb);
	return 1;
}

static int get_hdr_size_from_wr(struct ibscif_wr *wr)
{
	switch (wr->opcode) {
	case WR_UD:			return sizeof(struct ud_hdr);
	case WR_SEND:
	case WR_SEND_WITH_IMM:		return sizeof(struct send_hdr);
	case WR_RDMA_WRITE:
	case WR_RDMA_WRITE_WITH_IMM:	return sizeof(struct write_hdr);
	case WR_RDMA_READ:		return sizeof(struct read_req_hdr);
	case WR_ATOMIC_CMP_AND_SWP:	return sizeof(struct comp_swap_hdr);
	case WR_ATOMIC_FETCH_AND_ADD:	return sizeof(struct fetch_add_hdr);
	case WR_RDMA_READ_RSP:		return sizeof(struct read_rsp_hdr);
	case WR_ATOMIC_RSP:		return sizeof(struct atomic_rsp_hdr);
	case WR_RMA_RSP:		return sizeof(struct rma_rsp_hdr);
	default:			return 0;
	}
}

static int get_rma_addr_size_from_wr(struct ibscif_wr *wr)
{
	switch (wr->opcode) {
	case WR_UD:			return 0;
	case WR_SEND:
	case WR_SEND_WITH_IMM:
	case WR_RDMA_WRITE:
	case WR_RDMA_WRITE_WITH_IMM:
	case WR_RDMA_READ:		return wr->num_ds *
						sizeof(struct rma_addr);
	case WR_ATOMIC_CMP_AND_SWP:	return 0;
	case WR_ATOMIC_FETCH_AND_ADD:	return 0;
	case WR_RDMA_READ_RSP:		return 0;
	case WR_ATOMIC_RSP:		return 0;
	case WR_RMA_RSP:		return 0;
	default:			return 0;
	}
}

static int setup_rma_addrs(struct ibscif_wq *wq, struct ibscif_wr *wr)
{
	struct ibscif_ds *ds;
	int i;

	if (!wr->num_ds)
		return 1;

	for (i=0; i<wr->num_ds; i++) {
		ds = &wr->ds_list[i];
		if (!ds->current_mreg)
			ds->current_mreg =
				ibscif_mr_get_mreg(ds->mr, wq->qp->conn);

		if (!ds->current_mreg)
			return 0;
	}

	return 1;
}

/* when necessary SCIF will allocate temp buffer to align up cache line
 * offset.so we only need to use roffset to calculate the dma size.
 */
static inline int ibscif_dma_size(u32 len, u64 roffset)
{
	u32 head, tail;

	tail = (roffset + len) % 64;
	head = (64 - roffset % 64) % 64;
	if (len >= head + tail)
		return (len - head - tail);
	else
		return 0;
}

static void ibscif_send_ack(struct ibscif_qp *qp);

static int ibscif_try_fast_rdma(struct ibscif_wq *wq, struct ibscif_wr *wr)
{
	struct ibscif_qp *qp;
	int i, err;
	u64 loffset, roffset;
	u32 total_length, rdma_length, xfer_len;
	u64 raddress;
	u32 rkey;
	enum ib_access_flags access;
	u32 dma_size = 0;
	int rma_flag = 0;

	IBSCIF_PERF_SAMPLE(2, 0);

	switch (wr->opcode) {
	  case WR_RDMA_WRITE:
		raddress = wr->write.remote_address;
		rkey = wr->write.rkey;
		total_length = rdma_length = wr->length;
		access = IB_ACCESS_REMOTE_WRITE;
		break;

	  case WR_RDMA_READ:
		raddress = wr->read.remote_address;
		rkey = wr->read.rkey;
		total_length = rdma_length = wr->read.remote_length;
			/* wr->length is 0 */
		access = IB_ACCESS_REMOTE_READ;
		break;

	  default:
		return 0;
	}

	qp = wq->qp;

	if (unlikely(!qp->conn)) {
		printk(KERN_ALERT PFX "%s: ERROR: qp->conn == NULL\n",
			__func__);
		return 0;
	}

	if (!setup_rma_addrs(wq, wr)) {
		DEV_STAT(qp->dev, fast_rdma_fallback++);
		return 0;
	}

	roffset = IBSCIF_MR_VADDR_TO_OFFSET( rkey, raddress );

	for (i=0; i<wr->num_ds; i++) {
		if (rdma_length == 0)
			break;

		loffset = wr->ds_list[i].current_mreg->offset +
			  wr->ds_list[i].offset;
		xfer_len = min(wr->ds_list[i].length, rdma_length);
		if (xfer_len == 0)
			continue;

		IBSCIF_PERF_SAMPLE(3, 0);

		dma_size = ibscif_dma_size(xfer_len, roffset);

		if (i==wr->num_ds-1)
			rma_flag = dma_size ? SCIF_RMA_SYNC : 0;

		if (wr->opcode == WR_RDMA_WRITE) {
			err = scif_writeto(wq->qp->conn->ep, loffset,
					   xfer_len, roffset,
					   rma_flag|SCIF_RMA_ORDERED);
			if (err)
				printk(KERN_INFO PFX
					"%s(): error writing ordered message, "
					"size=%d, err=%d.\n",
					__func__, xfer_len, err);
		}
		else {
			err = scif_readfrom(wq->qp->conn->ep, loffset,
					    xfer_len, roffset, rma_flag);
			if (err)
				printk(KERN_INFO PFX
					"%s(): error reading the message, "
					"size=%d, err=%d.\n",
					__func__, xfer_len, err);
		}

		IBSCIF_PERF_SAMPLE(4, 0);

		if (err){
			DEV_STAT(qp->dev, fast_rdma_fallback++);
			return 0;
		}

		roffset += xfer_len;
		rdma_length -= xfer_len;
	}

	if (rdma_length)
		printk(KERN_INFO PFX "%s(): remaining rdma_length=%d.\n",
			__func__, rdma_length);

	IBSCIF_PERF_SAMPLE(5, 0);

	/* complete the wr */
	ibscif_clear_ds_refs(wr->ds_list, wr->num_ds);
	wr->state = WR_COMPLETED;
	wr->sar.rea.final_length = total_length - rdma_length;

	/* we can't call ibscif_process_sq_completions here because we
	 * are holding the sq lock. set the flag and let the upper level
	 * make the call
	 */
	wq->fast_rdma_completions = 1;

	if (wr->opcode == WR_RDMA_WRITE)
		DEV_STAT(qp->dev, fast_rdma_write++);
	else
		DEV_STAT(qp->dev, fast_rdma_read++);

	/* the fast rdma protocol doesn't send any packet, and thus can
	 * not piggyback any ack for the peer. send separate ack packet
	 * when necessary.
	 */
	if (qp->wire.sq.rx.last_seq_acked < qp->wire.sq.rx.last_in_seq ||
	    qp->wire.iq.rx.last_seq_acked < qp->wire.iq.rx.last_in_seq) {
		ibscif_send_ack(qp);
		DEV_STAT(qp->dev, fast_rdma_force_ack++);
	}

	IBSCIF_PERF_SAMPLE(8, 0);

	return 1;
}

/*
 * Setup for a fresh data descriptor.
 */
#define DS_SETUP(ds, mr, page_offset, page_index, ds_len_left)	\
do {								\
	mr = ds->mr;						\
	ds_len_left  = ds->length;				\
	page_offset  = ds->offset + (mr->addr & ~PAGE_MASK);	\
	page_index   = page_offset >> PAGE_SHIFT;		\
	page_offset &= ~PAGE_MASK;				\
} while(0)

/*
 * Setup for page crossing within a data descriptor.
 */
#define NEXT_PAGE(ds, mr, page_offset, page_index, ds_len_left)		\
do {									\
	if (!ds_len_left) {						\
		ds++;							\
		DS_SETUP(ds, mr, page_offset, page_index, ds_len_left);	\
	} else {							\
		page_index++;						\
		BUG_ON(!(mr->npages > page_index));			\
		page_offset = 0;					\
	}								\
} while(0)

/*
 * Setup the data descriptor, page, and offset for specified sequence number
 */
#define SETUP_BY_SEQ(wr, ds, mr, from_seq, wr_length, page_offset, 	\
		     page_index, ds_len_left, max_payload)		\
do {									\
	u32 i, frag_len_max;						\
									\
	DS_SETUP(ds, mr, page_offset, page_index, ds_len_left);		\
	for (i = wr->sar.seg.starting_seq; seq_before(i, from_seq); i++) {\
		num_frags = 0;						\
		payload_left = max_payload;				\
		while (payload_left && (num_frags < MAX_SKB_FRAGS)) {	\
			frag_len_max = min(ds_len_left, 		\
					  (u32)(PAGE_SIZE - page_offset));\
			if (wr_length > payload_left) {			\
				if (payload_left > frag_len_max) {	\
					ds_len_left -= frag_len_max;	\
					NEXT_PAGE(ds, mr, page_offset,	\
						  page_index, ds_len_left);\
				} else {				\
					frag_len_max = payload_left; 	\
					ds_len_left -= payload_left;	\
					page_offset += payload_left;	\
				}					\
			} else {					\
				if (wr_length > frag_len_max) {		\
					ds_len_left -= frag_len_max;	\
					NEXT_PAGE(ds, mr, page_offset,	\
						  page_index, ds_len_left);\
				} else {				\
					printk(KERN_ERR	PFX		\
						"from_seq (%d) botch wr"\
						" %p opcode %d length %d\n",\
					from_seq, wr, wr->opcode, wr_length);\
					return 0;			\
				}					\
			}						\
			wr_length    -= frag_len_max;			\
			payload_left -= frag_len_max;			\
			num_frags++;					\
		}							\
	}								\
} while(0)

int ibscif_xmit_wr(struct ibscif_wq *wq, struct ibscif_wr *wr, int tx_limit,
		   int retransmit, u32 from_seq, u32 *posted)
{
	struct ibscif_dev *dev;
	struct ibscif_qp *qp;
	struct ibscif_ds *ds;
	struct ibscif_mr *mr;
	int hdr_size, page_index, num_frags, num_xmited;
	u32 max_payload, wr_length, page_offset, ds_len_left, payload_left;

	/* Try to process RDMA read/write directly with SCIF functions.
	 * The usual reason for failure is that the remote memory has not
	 * yet been registered with SCIF. The normal packet based path
	 * should handle that.
	 */
	if (host_proxy && wq->qp->local_node_id>0 &&
	    wq->qp->remote_node_id==0) {
 		/* don't try fast rdma becasue we want to let the host do
		 * the data transfer
		 */
	}
	else if (fast_rdma) {
		num_xmited = 0;
		if (ibscif_try_fast_rdma(wq, wr))
			goto finish2;
	}

	if (!tx_limit) {
		printk(KERN_INFO PFX "%s() called with tx_limit of zero\n",
			__func__);
		return 0;
	}

	qp = wq->qp;
	dev = qp->dev;
	hdr_size = get_hdr_size_from_wr(wr);
	max_payload = qp->mtu - hdr_size;

	if (wr->use_rma) {
		struct sk_buff *skb;

		wr_length = wr->length;
		wr->sar.seg.starting_seq = from_seq;
		wr->sar.seg.ending_seq	 = from_seq;
		wr->state = WR_STARTED;

		num_xmited = 0;
		if (setup_rma_addrs(wq, wr)) {
			/* Make room in the header for RMA addresses */
			hdr_size += get_rma_addr_size_from_wr(wr);

			/* Allocate an initialized skb with PDU header. */
			skb = ibscif_alloc_pdu(dev, qp, wr, hdr_size,
					       from_seq, 0, wr_length, 0);
			if (likely(skb)) {
				ibscif_dev_queue_xmit(skb);
				num_xmited++;
				from_seq++;
			}
		}
		else
			printk(KERN_ALERT PFX
				"%s: fail to set up RMA addresses for the "
				"work request.\n", __func__);

		goto finish;
	}

	if (!wr->sar.seg.current_ds) {
		/*
		 * This is a fresh send so intialize the wr by setting
		 * the static parts of the header and sequence number
		 * range for this wr.
		 */
		wr_length = wr->length;
		wr->sar.seg.starting_seq = from_seq;
		wr->sar.seg.ending_seq	 = from_seq;
		if (wr_length > max_payload) {
			wr->sar.seg.ending_seq += (wr_length / max_payload);
			if (!(wr_length % max_payload))
				wr->sar.seg.ending_seq--;
		}

		wr->state = WR_STARTED;

		/*
		 * If this request has a payload, setup for fragmentation.
		 * Otherwise, send it on its way.
		 */
		if (wr_length) {
			ds = wr->ds_list;
			DS_SETUP(ds, mr, page_offset, page_index, ds_len_left);
		} else {
			num_xmited = ibscif_send_null_pdu(dev, qp, wr,
							  hdr_size);
			/* from_seq must always advanced even for null PDU */
			from_seq++;
			goto finish;
		}
	} else {
		/* We're picking up from a paritally sent request. */
		ds = wr->sar.seg.current_ds;
		mr = ds->mr;
		wr_length   = wr->sar.seg.wr_length_remaining;
		ds_len_left = wr->sar.seg.ds_length_remaining;
		page_index  = wr->sar.seg.current_page_index;
		page_offset = wr->sar.seg.current_page_offset;
		from_seq    = wr->sar.seg.next_seq;
	}

	/* Ok, let's break this bad-boy up. */
	num_xmited = 0;
	while (wr_length && (num_xmited < tx_limit) &&
	       (qp->state == QP_CONNECTED)) {
		struct sk_buff *skb;
		skb_frag_t *frag;

		/* Allocate an initialized skb with PDU header. */
		skb = ibscif_alloc_pdu(dev, qp, wr, hdr_size, from_seq,
				       min(wr_length, max_payload),
				       wr_length, retransmit &&
				       (num_xmited == (tx_limit - 1)));
		if (unlikely(!skb))
			break;

		/* Update sequence number for next pass. */
		from_seq++;

		/* Fill the skb fragment list. */
		frag = skb_shinfo(skb)->frags;
		num_frags = 0;
		payload_left = max_payload;

		while (payload_left && (num_frags < MAX_SKB_FRAGS)) {
			u32 frag_len_max;

			SET_PAGE(frag, mr->page[page_index]);
			frag->page_offset = page_offset;

			/* kfree_skb will release the reference */
			GET_PAGE(frag);

			frag_len_max = min(ds_len_left,
					   (u32)(PAGE_SIZE - page_offset));
			if (wr_length > payload_left) {
				if (payload_left > frag_len_max) {
					/* Deal with page boundary crossing. */
					frag->size   = frag_len_max;
					ds_len_left -= frag_len_max;
					NEXT_PAGE(ds, mr, page_offset,
						  page_index, ds_len_left);
				} else {
					frag->size   = payload_left;
					ds_len_left -= payload_left;
					page_offset += payload_left;
				}
			} else {
				if (wr_length > frag_len_max) {
					/* Deal with page boundary crossing. */
					frag->size   = frag_len_max;
					ds_len_left -= frag_len_max;
					NEXT_PAGE(ds, mr, page_offset,
						  page_index, ds_len_left);
				} else {
					frag->size    = wr_length;
					payload_left -= wr_length;
					wr_length = 0;
					num_frags++;
					break;
				}
			}

			wr_length    -= frag->size;
			payload_left -= frag->size;
			num_frags++;
			frag++;
		}
		skb_shinfo(skb)->nr_frags = num_frags;

		/* Check a fixup is needed because we ran out of frags. */
		if ((num_frags == MAX_SKB_FRAGS) && wr_length) {
			struct ibscif_full_frame *pdu =
				(struct ibscif_full_frame*)skb->data;
			skb->len = hdr_size + (max_payload - payload_left);
			skb->data_len = (max_payload - payload_left);
			pdu->ibscif.hdr.length = skb->data_len;
			pdu->ibscif.hdr.opcode = pdu->ibscif.hdr.opcode &
						 ~ibscif_last_flag;
		}

		/* Send it. */
		ibscif_dev_queue_xmit(skb);
		num_xmited++;
	}

	/*
	 * Update state. If this is a retransmit, don't update anything.
	 * If not and there's more to do on the wr, save state. Otherwise,
	 * setup for next wr.
	 */
	if (wr_length && !wr->use_rma) {
		wr->sar.seg.current_ds = ds;
		wr->sar.seg.wr_length_remaining = wr_length;
		wr->sar.seg.ds_length_remaining = ds_len_left;
		wr->sar.seg.current_page_index	= page_index;
		wr->sar.seg.current_page_offset = page_offset;
	} else {
finish:		if (wr->opcode != WR_UD)
			wr->state = WR_WAITING_FOR_ACK;
finish2:	wq->next_wr = (wq->next_wr + 1) % wq->size;
	}
	wr->sar.seg.next_seq = from_seq;
	if (posted)
		*posted = from_seq;

	return num_xmited;
}

static struct sk_buff *
ibscif_create_disconnect_hdr(struct ibscif_dev *dev, u32 src_qpn,
			     u32 dst_qpn, enum ibscif_reason reason)
{
	struct ibscif_full_frame *pdu;
	struct sk_buff *skb;

	skb = ibscif_alloc_tx_skb(dev, sizeof pdu->ibscif.disconnect, 0);
	if (unlikely(!skb)) {
		printk(KERN_ERR PFX "%s() can't allocate skb\n", __func__);
		return NULL;
	}

	pdu = (struct ibscif_full_frame *)skb->data;

	/* The eth_hdr and ack fields are set by the caller. */
	pdu->ibscif.disconnect.hdr.opcode = ibscif_op_disconnect;
	pdu->ibscif.disconnect.hdr.length = 0; /* Length has no meaning. */
	pdu->ibscif.disconnect.hdr.dst_qp = dst_qpn;
	pdu->ibscif.disconnect.hdr.src_qp = src_qpn;
	pdu->ibscif.disconnect.hdr.seq_num = 0; /* seq_num has no meaning. */
	pdu->ibscif.disconnect.hdr.hdr_size = sizeof(pdu->ibscif.disconnect);
	pdu->ibscif.disconnect.reason = reason;

	SET_SKB_DEV(skb, dev);
	SET_SKB_WR(skb, NULL);

	return skb;
}

void ibscif_send_disconnect(struct ibscif_qp *qp, enum ibscif_reason reason)
{
	struct ibscif_dev *dev = qp->dev;
	struct ibscif_full_frame *pdu;
	struct sk_buff *skb;

	if (qp->ibqp.qp_type == IB_QPT_UD)
		return;

	if (qp->loopback) {
		ibscif_loopback_disconnect(qp, reason);
		return;
	}

	if (unlikely(!qp->conn)) {
		printk(KERN_ALERT PFX "%s: ERROR: qp->conn == NULL\n",
			__func__);
		return;
	}

	skb = ibscif_create_disconnect_hdr(dev, qp->ibqp.qp_num,
					   qp->remote_qpn, reason);
	if (unlikely(!skb))
		return;

	SET_SKB_EP(skb, qp->conn->ep);

	pdu = (struct ibscif_full_frame *)skb->data;

	pdu->ibscif.disconnect.hdr.sq_ack_num = qp->wire.sq.rx.last_in_seq;
	pdu->ibscif.disconnect.hdr.iq_ack_num = qp->wire.iq.rx.last_in_seq;

	ibscif_dev_queue_xmit(skb);
}

static void ibscif_reflect_disconnect(struct ibscif_qp *qp,
				      struct base_hdr *hdr,
				      struct sk_buff *in_skb,
				      enum ibscif_reason reason)
{
	struct ibscif_full_frame *pdu;
	struct sk_buff *skb;

	if (!qp || IS_ERR(qp)) {
		if (qp != ERR_PTR(-ENOENT) && verbose)
			printk(KERN_ALERT PFX
				"%s: qp=%p hdr=%p in_skb=%p reason=%d\n",
				__func__, qp, hdr, in_skb, reason);
		return;
	}

	/* Don't send a disconnect for a disconnect. */
	if (ibscif_pdu_base_type(hdr->opcode) == ibscif_op_disconnect)
		return;

	if (!qp->conn || !qp->conn->ep)
		return;

	skb = ibscif_create_disconnect_hdr((void *)in_skb->dev, hdr->dst_qp,
					   hdr->src_qp, reason);
	if (unlikely(!skb))
		return;

	SET_SKB_EP(skb, qp->conn->ep);

	pdu = (struct ibscif_full_frame *)skb->data;

	pdu->ibscif.disconnect.hdr.sq_ack_num = 0; /* has no meaning. */
	pdu->ibscif.disconnect.hdr.iq_ack_num = 0; /* has no meaning. */

	ibscif_dev_queue_xmit(skb);
}

static struct sk_buff *ibscif_create_ack_hdr(struct ibscif_qp *qp, int size)
{
	struct ibscif_full_frame *pdu;
	struct sk_buff *skb;
	u32 sq_seq, iq_seq;

	if (unlikely(!qp->conn)) {
		printk(KERN_ALERT PFX "%s: ERROR: qp->conn == NULL\n",
			__func__);
		return NULL;
	}

	skb = ibscif_alloc_tx_skb(qp->dev, size, 0);
	if (unlikely(!skb)) {
		printk(KERN_ERR PFX "%s() can't allocate skb\n", __func__);
		return NULL;
	}

	SET_SKB_DEV(skb, qp->dev);
	SET_SKB_WR(skb, NULL);
	SET_SKB_EP(skb, qp->conn->ep);

	sq_seq = qp->wire.sq.rx.last_in_seq;
	iq_seq = qp->wire.iq.rx.last_in_seq;
	qp->wire.sq.rx.last_seq_acked = sq_seq;
	qp->wire.iq.rx.last_seq_acked = iq_seq;

	pdu = (struct ibscif_full_frame *)skb->data;

	/* The opcode field set by the caller. */
	pdu->ibscif.hdr.length = 0; /* Length has no meaning. */
	pdu->ibscif.hdr.dst_qp = qp->remote_qpn;
	pdu->ibscif.hdr.src_qp = qp->ibqp.qp_num;
	pdu->ibscif.hdr.seq_num = 0; /* seq_num has no meaning. */
	pdu->ibscif.hdr.sq_ack_num = sq_seq;
	pdu->ibscif.hdr.iq_ack_num = iq_seq;
	pdu->ibscif.hdr.hdr_size = size;

	return skb;
}

static void ibscif_send_ack(struct ibscif_qp *qp)
{
	struct ibscif_full_frame *pdu;
	struct sk_buff *skb;

	skb = ibscif_create_ack_hdr(qp, sizeof pdu->ibscif.ack);
	if (unlikely(!skb))
		return;

	pdu = (struct ibscif_full_frame *)skb->data;
	pdu->ibscif.ack.hdr.opcode = ibscif_op_ack;

	ibscif_dev_queue_xmit(skb);
}

static struct sk_buff *
ibscif_create_close_hdr(struct ibscif_conn *conn, int size)
{
	struct ibscif_full_frame *pdu;
	struct sk_buff *skb;

	if (unlikely(!conn)) {
		printk(KERN_ALERT PFX "%s: ERROR: conn == NULL\n", __func__);
		return NULL;
	}

	skb = ibscif_alloc_tx_skb(conn->dev, size, 0);
	if (unlikely(!skb)) {
		printk(KERN_ERR PFX "%s() can't allocate skb\n", __func__);
		return NULL;
	}

	SET_SKB_DEV(skb, conn->dev);
	SET_SKB_WR(skb, NULL);
	SET_SKB_EP(skb, conn->ep);

	pdu = (struct ibscif_full_frame *)skb->data;

	/* The opcode field set by the caller. */
	pdu->ibscif.hdr.length = 0; /* Length has no meaning. */
	pdu->ibscif.hdr.dst_qp = 0; /* unused */
	pdu->ibscif.hdr.src_qp = 0; /* unused */
	pdu->ibscif.hdr.seq_num = 0; /* seq_num has no meaning. */
	pdu->ibscif.hdr.sq_ack_num = 0; /* unused */
	pdu->ibscif.hdr.iq_ack_num = 0; /* unused */
	pdu->ibscif.hdr.hdr_size = size;

	return skb;
}

void ibscif_send_close(struct ibscif_conn *conn)
{
	struct ibscif_full_frame *pdu;
	struct sk_buff *skb;

	skb = ibscif_create_close_hdr(conn, sizeof pdu->ibscif.close);
	if (unlikely(!skb))
		return;

	pdu = (struct ibscif_full_frame *)skb->data;
	pdu->ibscif.close.hdr.opcode = ibscif_op_close;

	ibscif_dev_queue_xmit(skb);
}

void ibscif_send_reopen(struct ibscif_conn *conn)
{
	struct ibscif_full_frame *pdu;
	struct sk_buff *skb;

	skb = ibscif_create_close_hdr(conn, sizeof pdu->ibscif.close);
	if (unlikely(!skb))
		return;

	pdu = (struct ibscif_full_frame *)skb->data;
	pdu->ibscif.close.hdr.opcode = ibscif_op_reopen;

	ibscif_dev_queue_xmit(skb);
}

static struct sk_buff *ibscif_create_cm_hdr(struct ibscif_conn *conn, int size)
{
	struct ibscif_full_frame *pdu;
	struct sk_buff *skb;

	if (unlikely(!conn)) {
		printk(KERN_ALERT PFX "%s: ERROR: conn == NULL\n", __func__);
		return NULL;
	}

	skb = ibscif_alloc_tx_skb(conn->dev, size, 0);
	if (unlikely(!skb)) {
		printk(KERN_ERR PFX "%s() can't allocate skb\n", __func__);
		return NULL;
	}

	SET_SKB_DEV(skb, conn->dev);
	SET_SKB_WR(skb, NULL);
	SET_SKB_EP(skb, conn->ep);

	pdu = (struct ibscif_full_frame *)skb->data;

	pdu->ibscif.hdr.opcode = ibscif_op_cm;
	pdu->ibscif.hdr.length = 0; /* Length has no meaning. */
	pdu->ibscif.hdr.dst_qp = 0; /* unused */
	pdu->ibscif.hdr.src_qp = 0; /* unused */
	pdu->ibscif.hdr.seq_num = 0; /* seq_num has no meaning. */
	pdu->ibscif.hdr.sq_ack_num = 0; /* unused */
	pdu->ibscif.hdr.iq_ack_num = 0; /* unused */
	pdu->ibscif.hdr.hdr_size = size;

	return skb;
}

int ibscif_send_cm_req(struct ibscif_cm *cm_ctx)
{
	struct ibscif_full_frame *pdu;
	struct sk_buff *skb;

	skb = ibscif_create_cm_hdr(cm_ctx->conn,
				   sizeof pdu->ibscif.cm + cm_ctx->plen);
	if (unlikely(!skb))
		return -ENOMEM;

	pdu = (struct ibscif_full_frame *)skb->data;
	pdu->ibscif.cm.req_ctx	= (u64)(uintptr_t)cm_ctx;
	pdu->ibscif.cm.cmd = IBSCIF_CM_REQ;
	pdu->ibscif.cm.port = cm_ctx->remote_addr.sin_port;
	pdu->ibscif.cm.qpn = cm_ctx->qpn;
	pdu->ibscif.cm.plen = cm_ctx->plen;
	memcpy(pdu->ibscif.cm.pdata, cm_ctx->pdata, cm_ctx->plen);

	ibscif_dev_queue_xmit(skb);

	return 0;
}

int ibscif_send_cm_rep(struct ibscif_cm *cm_ctx)
{
	struct ibscif_full_frame *pdu;
	struct sk_buff *skb;

	skb = ibscif_create_cm_hdr(cm_ctx->conn,
				   sizeof pdu->ibscif.cm + cm_ctx->plen);
	if (unlikely(!skb))
		return -ENOMEM;

	pdu = (struct ibscif_full_frame *)skb->data;
	pdu->ibscif.cm.req_ctx = cm_ctx->peer_context;
	pdu->ibscif.cm.rep_ctx = (u64)cm_ctx;
	pdu->ibscif.cm.cmd = IBSCIF_CM_REP;
	pdu->ibscif.cm.qpn = cm_ctx->qpn;
	pdu->ibscif.cm.status = 0;
	pdu->ibscif.cm.plen = cm_ctx->plen;
	memcpy(pdu->ibscif.cm.pdata, cm_ctx->pdata, cm_ctx->plen);

	ibscif_dev_queue_xmit(skb);

	return 0;
}

int ibscif_send_cm_rej(struct ibscif_cm *cm_ctx, const void *pdata, u8 plen)
{
	struct ibscif_full_frame *pdu;
	struct sk_buff *skb;

	skb = ibscif_create_cm_hdr(cm_ctx->conn, sizeof pdu->ibscif.cm + plen);
	if (unlikely(!skb))
		return -ENOMEM;

	pdu = (struct ibscif_full_frame *)skb->data;
	pdu->ibscif.cm.req_ctx = cm_ctx->peer_context;
	pdu->ibscif.cm.cmd = IBSCIF_CM_REJ;
	pdu->ibscif.cm.status = -ECONNREFUSED;
	pdu->ibscif.cm.plen = (u32)plen;
	memcpy(pdu->ibscif.cm.pdata, pdata, plen);

	ibscif_dev_queue_xmit(skb);

	return 0;
}

int ibscif_send_cm_rtu(struct ibscif_cm *cm_ctx)
{
	struct ibscif_full_frame *pdu;
	struct sk_buff *skb;

	skb = ibscif_create_cm_hdr(cm_ctx->conn, sizeof pdu->ibscif.cm);
	if (unlikely(!skb))
		return -ENOMEM;

	pdu = (struct ibscif_full_frame *)skb->data;
	pdu->ibscif.cm.rep_ctx = cm_ctx->peer_context;
	pdu->ibscif.cm.cmd = IBSCIF_CM_RTU;

	ibscif_dev_queue_xmit(skb);

	return 0;
}

/* ---------------------- tx routines above this line ---------------------- */
/* ---------------------- rx routines below this line ---------------------- */

static void ibscif_protocol_error(struct ibscif_qp *qp,
				  enum ibscif_reason reason)
{
	printk(KERN_NOTICE PFX "Disconnect due to protocol error %d\n", reason);
	ibscif_qp_internal_disconnect(qp, reason);
}

int ibscif_process_sq_completions(struct ibscif_qp *qp)
{
	struct ibscif_cq *cq = to_cq(qp->ibqp.send_cq);
	struct ibscif_wq *sq = &qp->sq;
	struct ibscif_wr *wr;
	struct ibscif_wc *wc;
	int index, err = 0, i;

	spin_lock_bh(&sq->lock);

	/* Prevent divide by zero traps on wrap math. */
	if (!sq->size)
		goto out;

	/* Iterate the send queue looking for defered completions. */
	for (i=sq->completions; i<sq->depth; i++) {
		index = (sq->head + i) % sq->size;

		wr = ibscif_get_wr(sq, index);
		if (wr->state != WR_COMPLETED)
			break;

		sq->completions++;
		sq->reap++;

		/* IQ request completed; update the throttling variables. */
		if ((wr->opcode == WR_RDMA_READ)	  ||
		    (wr->opcode == WR_ATOMIC_CMP_AND_SWP) ||
		    (wr->opcode == WR_ATOMIC_FETCH_AND_ADD)) {
			BUG_ON(!atomic_read(&qp->or_depth));
			atomic_dec(&qp->or_depth);
			atomic_dec(&qp->or_posted);
		}

		/* See if we need to generate a completion. */
		if (!(wr->flags & IB_SEND_SIGNALED))
			continue;

		err = ibscif_reserve_cqe(cq, &wc);
		if (unlikely(err))
			break;

		wc->ibwc.qp	  = &qp->ibqp;
		wc->ibwc.src_qp	  = qp->remote_qpn;
		wc->ibwc.wr_id	  = wr->id;
		wc->ibwc.opcode	  = to_ib_wc_opcode(
					(enum ib_wr_opcode)wr->opcode);
		wc->ibwc.wc_flags = (((enum ib_wr_opcode)wr->opcode ==
					IB_WR_RDMA_WRITE_WITH_IMM) ||
				     ((enum ib_wr_opcode)wr->opcode ==
					IB_WR_SEND_WITH_IMM)) ?
						IB_WC_WITH_IMM : 0;
		wc->ibwc.status	  = IB_WC_SUCCESS;
		wc->ibwc.ex.imm_data = 0;
		wc->ibwc.port_num = 1;
		wc->ibwc.byte_len = (((enum ib_wr_opcode)wr->opcode ==
					IB_WR_RDMA_READ) ||
				     ((enum ib_wr_opcode)wr->opcode ==
					IB_WR_ATOMIC_CMP_AND_SWP) ||
				     ((enum ib_wr_opcode)wr->opcode ==
					IB_WR_ATOMIC_FETCH_AND_ADD)) ?
						wr->sar.rea.final_length : 0;
		wc->wq	 = sq;
		wc->reap = sq->reap;
		sq->reap = 0;

		ibscif_append_cqe(cq, wc, 0);
	}
out:
	spin_unlock_bh(&sq->lock);

	ibscif_notify_cq(cq);
	return err;
}

static int ibscif_schedule_rx_completions(struct ibscif_qp *qp, int iq_flag,
					  struct ibscif_rx_state *rx)
{
	struct ibscif_cq *cq = to_cq(qp->ibqp.recv_cq);
	struct ibscif_wq *wq;
	struct ibscif_wr *wr;
	struct ibscif_wc *wc;
	u32 last_in_seq;
	int index, err, i;

	wq = iq_flag ? &qp->sq /* yep, the SQ */ : &qp->rq;
	last_in_seq = rx->last_in_seq;

	/* Prevent divide by zero traps on wrap math. */
	if (!wq->size)
		return 0;

	spin_lock_bh(&wq->lock);
	for (i=wq->completions; i<wq->depth; i++) {
		index = (wq->head + i) % wq->size;

		wr = ibscif_get_wr(wq, index);

		/* Skip over non-IQ entries. */
		if (iq_flag &&
		    ((wr->opcode == WR_UD)	      ||
		     (wr->opcode == WR_SEND)	      ||
		     (wr->opcode == WR_SEND_WITH_IMM) ||
		     (wr->opcode == WR_RDMA_WRITE)    ||
		     (wr->opcode == WR_RDMA_WRITE_WITH_IMM)))
			continue;

		/*
		 * If this WR hasn't seen the final segment in sequence then
		 * there is nothing more to process in this queue.  We use the
		 * last seen state as a qualifier because last_packet_seq will
		 * be uninitialized until last packet is seen.
		 */
		if ((wr->state != WR_LAST_SEEN) ||
		    seq_before(last_in_seq, wr->sar.rea.last_packet_seq))
			break;

		/* Clear references on memory regions. */
		ibscif_clear_ds_refs(wr->ds_list, wr->num_ds);

		if (iq_flag) {
			/*
			 * Completed IQ replies are defered until earlier
			 * non-IQ WR have completed.  This is determined
			 * with a second iteration of the WQ below.
			 */
			wr->state = WR_COMPLETED;
			continue; /* Look for more IQ completions. */
		}

		/* All receive queue completions are done here. */
		err = ibscif_reserve_cqe(cq, &wc);
		if (unlikely(err)) {
			spin_unlock_bh(&wq->lock);
			return err;
		}

		wc->ibwc.qp	  = &qp->ibqp;
		wc->ibwc.src_qp	  = qp->remote_qpn;
		wc->ibwc.wr_id	  = wr->id;
		wc->ibwc.status	  = IB_WC_SUCCESS;
		wc->ibwc.byte_len = wr->sar.rea.final_length;
		wc->ibwc.port_num = 1;

		if (ibscif_pdu_is_immed(wr->sar.rea.opcode)) {
			DEV_STAT(qp->dev, recv_imm++);
			wc->ibwc.opcode	  = IB_WC_RECV_RDMA_WITH_IMM;
			wc->ibwc.ex.imm_data = wr->sar.rea.immediate_data;
		} else {
			DEV_STAT(qp->dev, recv++);
			wc->ibwc.opcode	  = IB_WC_RECV;
			wc->ibwc.ex.imm_data = 0;
		}

		wc->wq	 = wq;
		wc->reap = 1;
		wq->completions++;

		ibscif_append_cqe(cq, wc,
				  !!ibscif_pdu_is_se(wr->sar.rea.opcode));
	}
	spin_unlock_bh(&wq->lock);

	/* If this was the recieve queue, there is no more processing to do */
	if (!iq_flag) {
		ibscif_notify_cq(cq);
		return 0;
	}

	err = ibscif_process_sq_completions(qp);
	if (unlikely(err))
		return err;

	/*
	 * If we just created room for a backlogged IQ stream request
	 * and there is a tx window, reschedule to get it sent.
	 */
	if ((atomic_read(&qp->or_posted) > atomic_read(&qp->or_depth)) &&
	    (atomic_read(&qp->or_depth) < qp->max_or)		       &&
	    ibscif_tx_window(&qp->wire.sq.tx))
		qp->schedule |= SCHEDULE_RESUME | SCHEDULE_SQ;

	return 0;
}

static enum ibscif_schedule
ibscif_process_wq_ack(struct ibscif_wq *wq, u32 seq_num)
{
	struct ibscif_tx_state *tx = &wq->wirestate->tx;
	enum ibscif_schedule status = 0;
	int throttled, index, err = 0, i;

	if (!wq->size || !wq->depth)
		return 0;

	/* If this is old news, get out. */
	if (!seq_after(seq_num, tx->last_ack_seq_recvd))
		return 0;

	/* Capture if window was closed before updating. */
	throttled = !ibscif_tx_window(tx);
	tx->last_ack_seq_recvd = seq_num;

	/*
	 * If were were throttled and now have an open window or
	 * simply up to date, resume streaming transfers.  This
	 * can be overwritten with other schedule states below.
	 */
	if (throttled && ibscif_tx_window(tx))
		status = SCHEDULE_RESUME;

	spin_lock_bh(&wq->lock);
	for (i=wq->completions; i<wq->depth; i++) {
		struct ibscif_wr *wr;

		index = (wq->head + i) % wq->size;

		wr = ibscif_get_wr(wq, index);

		/* Get out if the WR hasn't been scheduled. */
		if (wr->state == WR_WAITING)
			break;

		if (seq_after(wr->sar.seg.ending_seq, seq_num)) {

			if ((wr->state == WR_STARTED) &&
			    !ibscif_tx_unacked_window(tx))
				status = SCHEDULE_RESUME;

			break;
		}

		/* We seem to have a completed WQ element. */

		if (is_iq(wq)) {
			/*
			 * We have a completed IQ reply.
			 * Clear references to the memory region.
			 */
			ibscif_clear_ds_refs(wr->ds_list, wr->num_ds);

			/*
			 * It's more effecient to retire an IQ wqe manually
			 * here instead of calling ibscif_retire_wqes().
			 */
			wq->head   = (wq->head + 1) % wq->size;
			wq->depth -= 1;

		} else if ((wr->opcode == WR_RDMA_READ)		  ||
			   (wr->opcode == WR_ATOMIC_CMP_AND_SWP)  ||
			   (wr->opcode == WR_ATOMIC_FETCH_AND_ADD)||
			   (wr->opcode == WR_UD && wr->use_rma)   ||
			   (wr->opcode == WR_SEND && wr->use_rma) ||
			   (wr->opcode == WR_SEND_WITH_IMM && wr->use_rma) ||
			   (wr->opcode == WR_RDMA_WRITE && wr->use_rma)    ||
			   (wr->opcode == WR_RDMA_WRITE_WITH_IMM &&
				wr->use_rma)) {
			/*
			 * We have a request acknowledgment.
			 * Note the state change so it isn't retried.
			 *
			 * BTW, these request types are completed in the
			 * ibscif_schedule_rx_completions() routine when
			 * the data has arrived.
			 */
			if (wr->state == WR_WAITING_FOR_ACK)
				wr->state = WR_WAITING_FOR_RSP;

		} else if (wr->state != WR_COMPLETED) {
			/* Request is complete so no need to keep references. */
			ibscif_clear_ds_refs(wr->ds_list, wr->num_ds);
			wr->state = WR_COMPLETED;
		}
	}
	spin_unlock_bh(&wq->lock);

	if (is_sq(wq)) {
		err = ibscif_process_sq_completions(wq->qp);
		if (unlikely(err)) {
			printk(KERN_ALERT PFX
				"%s: sq completion error: err=%d \n",
				__func__, err);
			ibscif_protocol_error(wq->qp, IBSCIF_REASON_QP_FATAL);
			status = 0;
		}
	}

	return status;
}

static void ibscif_process_ack(struct ibscif_qp *qp, struct base_hdr *hdr)
{
	qp->schedule |= ibscif_process_wq_ack(&qp->sq,
					      hdr->sq_ack_num) | SCHEDULE_SQ;
	qp->schedule |= ibscif_process_wq_ack(&qp->iq,
					      hdr->iq_ack_num) | SCHEDULE_IQ;
}

/* Note that the WQ lock is held on success. */
static struct ibscif_wr *ibscif_reserve_wqe(struct ibscif_wq *wq)
{
	int err;

	spin_lock_bh(&wq->lock);

	if (unlikely(wq->qp->state != QP_CONNECTED)) {
		err = -ENOTCONN;
		goto out;
	}
	if (unlikely(!wq->size)) {
		err = -ENOSPC;
		goto out;
	}
	if (unlikely(wq->depth == wq->size)) {
		err = -ENOBUFS;
		goto out;
	}

	return ibscif_get_wr(wq, wq->tail);
out:
	spin_unlock_bh(&wq->lock);
	return ERR_PTR(err);
}

/* Note that this assumes the WQ lock is currently held. */
static void ibscif_append_wqe(struct ibscif_wq *wq)
{
	DEV_STAT(wq->qp->dev, wr_opcode[ibscif_get_wr(wq, wq->tail)->opcode]++);
	ibscif_append_wq(wq);
	spin_unlock_bh(&wq->lock);
}

static struct ibscif_wr* ibscif_wr_by_msg_id(struct ibscif_wq *wq, u32 msg_id)
{
	struct ibscif_wr *wr;
	int size = wq->size;

	if (!size)
		return NULL;

	wr = ibscif_get_wr(wq, msg_id % size);
	if (wr->use_rma)
		return (wr->rma_id == msg_id) ? wr : NULL;
	else
		return (wr->msg_id == msg_id) ? wr : NULL;
}

static int ibscif_ds_dma(struct ibscif_qp *qp, struct page **page,
			 u32 page_offset, struct sk_buff *skb, u32 dma_len,
			 int head_copied)
{
	void *dst, *src = skb->data;
	u32 copy_len;

	while (dma_len) {
		copy_len = min(dma_len, (u32)PAGE_SIZE - page_offset);

		dst = ibscif_map_dst(*page) + page_offset;
		head_copied = ibscif_atomic_copy(dst, src, copy_len,
						 head_copied);
		ibscif_unmap_dst(*page, dst);

		src	+= copy_len;
		dma_len -= copy_len;

		page++;
		page_offset = 0;
	}

	return head_copied;
}

static int ibscif_place_data(struct ibscif_qp *qp, struct ibscif_wr *wr,
			     struct sk_buff *skb, u32 length, u32 offset,
			     u32 seq_num)
{
	struct ibscif_ds *ds;
	struct ibscif_mr *mr;
	int seg_num, page_index;
	u32 dma_len, ds_offset, page_offset;
	int head_copied = 0;

	if (!length) {
		ds = NULL;
		dma_len = 0;
		ds_offset = 0;
		goto no_data;
	}

	/* See if we can use our ds cache. */
	if (likely((wr->sar.rea.current_ds) &&
		   (wr->sar.rea.last_seen_seq == seq_num - 1))) {
		/* Take the cached entires. */
		ds = wr->sar.rea.current_ds;
		mr = ds->mr;
		ds_offset = wr->sar.rea.current_ds_offset;
		seg_num = (ds - wr->ds_list) / sizeof *wr->ds_list;
	} else {
		ds_offset = offset;
		ds = wr->ds_list;
		seg_num = 0;
		while ((ds_offset >= ds->length) && (seg_num < wr->num_ds)) {
			ds_offset -= ds->length;
			ds++;
			seg_num++;
		}
next_ds:
		if (unlikely(seg_num >= wr->num_ds))
			return -EMSGSIZE;
		/*
		 * A memory region which may have posted receives against it can
		 * still be freed, therefore, we need to burn the cycles here to
		 * make sure it's still valid.  We'll take a reference on it now
		 * that data is coming in.
		 */
		if (!ds->in_use) {
			mr = ibscif_get_mr(ds->lkey);
			if (unlikely(IS_ERR(mr)))
				return PTR_ERR(mr);
			ds->in_use = 1;
			if (unlikely(mr != ds->mr))
				return -ENXIO;
			if (unlikely(!(mr->access & IB_ACCESS_LOCAL_WRITE)))
				return -EACCES;
		} else
			mr = ds->mr;
	}

	/* Place data for this descriptor.  Routine will handle page
 	 * boundary crossings.
 	 */
	page_offset  = ds->offset + ds_offset + (mr->addr & ~PAGE_MASK);
	page_index   = page_offset >> PAGE_SHIFT;
	page_offset &= ~PAGE_MASK;

	dma_len = min(ds->length - ds_offset, length);
	head_copied = ibscif_ds_dma(qp, &mr->page[page_index], page_offset,
				    skb, dma_len, head_copied);
	length -= dma_len;
	if (length) {
		ds++;
		seg_num++;
		ds_offset = 0;
		skb_pull(skb, dma_len);
		goto next_ds;
	}
no_data:
	wr->sar.rea.last_seen_seq = seq_num;

	if (ds && ((ds_offset + dma_len) < ds->length)) {
		wr->sar.rea.current_ds = ds;
		wr->sar.rea.current_ds_offset = ds_offset + dma_len;
	} else {
		/* Force a validation of the next ds. */
		wr->sar.rea.current_ds = NULL;
	}

	return 0;
}

static int ibscif_process_ud(struct ibscif_qp *qp, union ibscif_pdu *pdu,
			     struct sk_buff *skb)
{
	struct ibscif_wr *wr;
	int err;
	int grh_size = 40;
	int msg_id;

	if (unlikely(qp->ibqp.qp_type != IB_QPT_UD)) {
		printk(KERN_ALERT PFX
			"%s: UD packet received on non-UD QP\n", __func__);
		return -EINVAL;
	}

	/* Only one pdu is allowed for one UD packet, otherwise drop the pdu */
	if (unlikely(pdu->ud.msg_length != pdu->hdr.length ||
		     pdu->ud.msg_offset)) {
		printk(KERN_INFO PFX
			"%s: dropping fragmented UD packet. "
			"total_length=%d msg_length=%d msg_offset=%d\n",
			__func__, pdu->hdr.length, pdu->ud.msg_length,
			pdu->ud.msg_offset);
		return -EINVAL;
	}

	spin_lock_bh(&qp->rq.lock);
	if (unlikely(qp->rq.ud_msg_id >= qp->rq.next_msg_id)) {
		spin_unlock_bh(&qp->rq.lock);
		printk(KERN_ALERT PFX
			"%s: ERROR: message arrives before recv is posted. "
			"msg_id=%d, rq.next_msg_id=%d\n",
			__func__, pdu->send.msg_id, qp->rq.next_msg_id);
		return -EBADRQC;
	}
	msg_id = qp->rq.ud_msg_id++;
	spin_unlock_bh(&qp->rq.lock);

	wr = ibscif_wr_by_msg_id(&qp->rq, msg_id);
	if (unlikely(!wr))
		return -EBADR;

	if (unlikely((pdu->ud.msg_length + grh_size) > wr->length))
		return -EMSGSIZE;

	/* GRH is included as part of the received message */
	skb_pull(skb, sizeof(pdu->ud)-grh_size);

	err = ibscif_place_data(qp, wr, skb, pdu->hdr.length+grh_size,
				pdu->ud.msg_offset, pdu->hdr.seq_num);
	if (unlikely(err))
		return err;

	wr->state = WR_LAST_SEEN;
	wr->sar.rea.opcode	    = pdu->hdr.opcode;
	wr->sar.rea.last_packet_seq = 0;
	wr->sar.rea.immediate_data  = 0;
	wr->sar.rea.final_length    = pdu->ud.msg_length+grh_size;

	return 0;
}

static int ibscif_process_send(struct ibscif_qp *qp, union ibscif_pdu *pdu,
			       struct sk_buff *skb)
{
	struct ibscif_wr *wr;
	int err;

	spin_lock_bh(&qp->rq.lock);
	if (unlikely(pdu->send.msg_id >= qp->rq.next_msg_id)) {
		spin_unlock_bh(&qp->rq.lock);
		printk(KERN_ALERT PFX
			"%s: ERROR: message arrives before recv is posted. "
			"msg_id=%d, rq.next_msg_id=%d\n",
			__func__, pdu->send.msg_id, qp->rq.next_msg_id);
		return -EBADRQC;
	}
	spin_unlock_bh(&qp->rq.lock);

	wr = ibscif_wr_by_msg_id(&qp->rq, pdu->send.msg_id);
	if (unlikely(!wr))
		return -EBADR;

	if (unlikely(pdu->send.msg_length > wr->length))
		return -EMSGSIZE;

	if (unlikely(pdu->send.msg_offset > pdu->send.msg_length))
		return -EINVAL;

	if (unlikely((pdu->hdr.length + pdu->send.msg_offset) > wr->length))
		return -ESPIPE;

	skb_pull(skb, sizeof(pdu->send));

	err = ibscif_place_data(qp, wr, skb, pdu->hdr.length,
				pdu->send.msg_offset, pdu->hdr.seq_num);
	if (unlikely(err))
		return err;

	if (ibscif_pdu_is_last(pdu->hdr.opcode)) {
		/*
		 * We've got the last of the message data.
		 * We always assume immediate data; if not needed,
		 * no harm, on foul.
		 */
		wr->state = WR_LAST_SEEN;
		wr->sar.rea.opcode = pdu->hdr.opcode;
		wr->sar.rea.last_packet_seq = pdu->hdr.seq_num;
		wr->sar.rea.immediate_data = pdu->send.immed_data;
		wr->sar.rea.final_length = pdu->send.msg_length;
	}

	return 0;
}

static int ibscif_process_write(struct ibscif_qp *qp, union ibscif_pdu *pdu,
				struct sk_buff *skb)
{
	struct ibscif_wr *wr;
	struct ibscif_mr *mr;
	u64 rdma_addr;
	u32 rdma_len, page_offset;
	int page_index;

	if (unlikely(!(qp->access & IB_ACCESS_REMOTE_WRITE)))
		return -EACCES;

	/* Writes with immediate data consume an rq wqe. */
	if (ibscif_pdu_is_immed(pdu->hdr.opcode)) {
		spin_lock_bh(&qp->rq.lock);
		if (unlikely(pdu->write.msg_id >= qp->rq.next_msg_id)) {
			spin_unlock_bh(&qp->rq.lock);
			printk(KERN_ALERT PFX
				"%s: ERROR: message arrives before recv is "
				"posted. msg_id=%d, rq.next_msg_id=%d\n",
				__func__, pdu->write.msg_id,
				qp->rq.next_msg_id);
			return -EBADRQC;
		}
		spin_unlock_bh(&qp->rq.lock);

		wr = ibscif_wr_by_msg_id(&qp->rq, pdu->write.msg_id);
		if (unlikely(!wr))
			return -EBADR;
	} else
		wr = NULL;

	skb_pull(skb, sizeof(pdu->write));

	rdma_addr = pdu->write.rdma_address;
	rdma_len  = pdu->hdr.length;
	if (unlikely((rdma_addr + (rdma_len - 1)) < rdma_addr))
		return -EOVERFLOW;

	mr = ibscif_validate_mr(pdu->write.rdma_key,
				rdma_addr, rdma_len, qp->ibqp.pd,
				IB_ACCESS_REMOTE_WRITE);
	if (unlikely(IS_ERR(mr)))
		return PTR_ERR(mr);

	page_offset = rdma_addr & ~PAGE_MASK;
	page_index  = ((rdma_addr - mr->addr) + (mr->addr & ~PAGE_MASK)) >>
				PAGE_SHIFT;

	ibscif_ds_dma(qp, &mr->page[page_index], page_offset, skb, rdma_len, 0);

	ibscif_put_mr(mr);

	if (wr) {
		wr->sar.rea.final_length += rdma_len;
		if (ibscif_pdu_is_last(pdu->hdr.opcode)) {
			/* We've got the last of the write data. */
			wr->state = WR_LAST_SEEN;
			wr->sar.rea.opcode = pdu->hdr.opcode;
			wr->sar.rea.last_packet_seq = pdu->hdr.seq_num;
			wr->sar.rea.immediate_data = pdu->write.immed_data;
		}
	}

	return 0;
}

static int ibscif_process_read(struct ibscif_qp *qp, union ibscif_pdu *pdu,
			       struct sk_buff *skb)
{
	struct ibscif_wr *wr;
	struct ibscif_mr *mr;
	u64 rdma_addr;
	u32 rdma_len;

	if (unlikely(!(qp->access & IB_ACCESS_REMOTE_READ)))
		return -EACCES;

	rdma_addr = pdu->read_req.rdma_address;
	rdma_len  = pdu->read_req.rdma_length;
	if (unlikely((rdma_addr + (rdma_len - 1)) < rdma_addr))
		return -EOVERFLOW;

	mr = ibscif_validate_mr(pdu->read_req.rdma_key,
				rdma_addr, rdma_len, qp->ibqp.pd,
				IB_ACCESS_REMOTE_READ);
	if (unlikely(IS_ERR(mr)))
		return PTR_ERR(mr);

	wr = ibscif_reserve_wqe(&qp->iq);
	if (unlikely(IS_ERR(wr))) {
		ibscif_put_mr(mr);
		return PTR_ERR(wr);
	}

	memset(&wr->sar, 0, sizeof wr->sar);

	wr->opcode = WR_RDMA_READ_RSP;
	wr->state  = WR_WAITING;
	wr->length = rdma_len;
	wr->msg_id = pdu->read_req.rdma_id;
	wr->num_ds = 1;
	wr->ds_list[0].mr     = mr;
	wr->ds_list[0].offset = rdma_addr - mr->addr;
	wr->ds_list[0].length = rdma_len;
	wr->ds_list[0].in_use = 1;

	ibscif_append_wqe(&qp->iq);
	qp->schedule |= SCHEDULE_RESUME | SCHEDULE_IQ;

	return 0;
}

static int ibscif_process_read_rsp(struct ibscif_qp *qp, union ibscif_pdu *pdu,
				   struct sk_buff *skb)
{
	struct ibscif_wr *wr;
	int err;

	/* Find the requesting sq wr. */
	wr = ibscif_wr_by_msg_id(&qp->sq, pdu->read_rsp.rdma_id);
	if (unlikely(!wr))
		return -EBADR;
	if (unlikely(wr->opcode != WR_RDMA_READ))
		return -ENOMSG;

	skb_pull(skb, sizeof(pdu->read_rsp));

	err = ibscif_place_data(qp, wr, skb, pdu->hdr.length,
				pdu->read_rsp.rdma_offset, pdu->hdr.seq_num);
	if (unlikely(err))
		return err;

	if (ibscif_pdu_is_last(pdu->hdr.opcode)) {
		/* We've got the last of the read data. */
		wr->state = WR_LAST_SEEN;
		wr->sar.rea.opcode = pdu->hdr.opcode;
		wr->sar.rea.last_packet_seq = pdu->hdr.seq_num;
		wr->sar.rea.final_length = pdu->read_rsp.rdma_offset +
					   pdu->hdr.length;
	}

	return 0;
}

static int ibscif_process_atomic_req(struct ibscif_qp *qp,
				     union ibscif_pdu *pdu,
				     struct sk_buff *skb)
{
	struct ibscif_wr *wr;
	struct ibscif_mr *mr;
	struct page *page;
	u64 *addr;
	u32 offset, rkey, msg_id;
	u16 opcode;

	if (unlikely(!(qp->access & IB_ACCESS_REMOTE_ATOMIC)))
		return -EACCES;

	opcode = ibscif_pdu_base_type(pdu->hdr.opcode);
	if (opcode == ibscif_op_comp_swap) {
		addr = (u64 *)pdu->comp_swap.atomic_address;
		rkey = pdu->comp_swap.atomic_key;
		msg_id = pdu->comp_swap.atomic_id;
	} else {
		addr = (u64 *)pdu->fetch_add.atomic_address;
		rkey = pdu->fetch_add.atomic_key;
		msg_id = pdu->fetch_add.atomic_id;
	}

	if (unlikely((u64)addr & (sizeof *addr - 1)))
		return -EADDRNOTAVAIL;
	if (unlikely((addr + (sizeof *addr - 1)) < addr))
		return -EOVERFLOW;

	mr = ibscif_validate_mr(rkey, (u64)addr, sizeof *addr, qp->ibqp.pd,
				IB_ACCESS_REMOTE_ATOMIC);
	if (unlikely(IS_ERR(mr)))
		return PTR_ERR(mr);

	wr = ibscif_reserve_wqe(&qp->iq);
	if (unlikely(IS_ERR(wr))) {
		ibscif_put_mr(mr);
		return PTR_ERR(wr);
	}

	/* Determine which page to map. */
	offset	= ((u64)addr - mr->addr) + (mr->addr & ~PAGE_MASK);
	page	= mr->page[offset >> PAGE_SHIFT];
	offset &= ~PAGE_MASK;

	/* Lock to perform the atomic operation atomically. */
	spin_lock_bh(&qp->dev->atomic_op);

	addr = ibscif_map_src(page) + offset;
	wr->atomic_rsp.orig_data = *addr;
	if (opcode == ibscif_op_fetch_add)
		*addr += pdu->fetch_add.add_data;
	else if (wr->atomic_rsp.orig_data ==
		 pdu->comp_swap.comp_data)
		*addr  = pdu->comp_swap.swap_data;
	ibscif_unmap_src(page, addr);

	ibscif_put_mr(mr);

	/* Atomic operation is complete. */
	spin_unlock_bh(&qp->dev->atomic_op);

	memset(&wr->sar, 0, sizeof wr->sar);

	wr->opcode = WR_ATOMIC_RSP;
	wr->state  = WR_WAITING;
	wr->length = 0;
	wr->msg_id = msg_id;
	wr->num_ds = 0;
	wr->atomic_rsp.opcode = (opcode==ibscif_op_comp_swap)?
					ibscif_op_comp_swap_rsp :
					ibscif_op_fetch_add_rsp;
	/* The wr->atomic_rsp.orig_data field was set above. */

	ibscif_append_wqe(&qp->iq);
	qp->schedule |= SCHEDULE_RESUME | SCHEDULE_IQ;

	return 0;
}

static int ibscif_process_atomic_rsp(struct ibscif_qp *qp,
				     union ibscif_pdu *pdu,
				     struct sk_buff *skb)
{
	struct ibscif_wr *wr;
	u16 opcode;
	int err;

	if (unlikely(!ibscif_pdu_is_last(pdu->atomic_rsp.hdr.opcode)))
		return -EINVAL;

	/* Find the requesting sq wr. */
	wr = ibscif_wr_by_msg_id(&qp->sq, pdu->atomic_rsp.atomic_id);
	if (unlikely(!wr))
		return -EBADR;

	opcode = ibscif_pdu_base_type(pdu->hdr.opcode);
	if (unlikely(wr->opcode !=
		((opcode == ibscif_op_comp_swap_rsp) ?
			WR_ATOMIC_CMP_AND_SWP : WR_ATOMIC_FETCH_AND_ADD)))
		return -ENOMSG;

	skb_pull(skb, (unsigned long)&pdu->atomic_rsp.orig_data -
		      (unsigned long)pdu);

	err = ibscif_place_data(qp, wr, skb, sizeof pdu->atomic_rsp.orig_data,
				0, pdu->hdr.seq_num);
	if (unlikely(err))
		return err;

	wr->state = WR_LAST_SEEN;
	wr->sar.rea.opcode	    = pdu->hdr.opcode;
	wr->sar.rea.last_packet_seq = pdu->hdr.seq_num;
	wr->sar.rea.final_length    = sizeof pdu->atomic_rsp.orig_data;

	return 0;
}

static int ibscif_process_disconnect(struct ibscif_qp *qp,
				     union ibscif_pdu *pdu,
				     struct sk_buff *skb)
{
	ibscif_qp_remote_disconnect(qp, pdu->disconnect.reason);
	return 0;
}

static int ibscif_process_send_rma(struct ibscif_qp *qp,
				   union ibscif_pdu *pdu,
				   struct sk_buff *skb)
{
	struct ibscif_ds *ds;
	struct ibscif_wr *wr;
	struct ibscif_mr *mr;
	struct ibscif_mreg_info *mreg;
	u32 num_rma_addrs;
	u64 rma_offset;
	u32 rma_length;
	u32 total;
	int seg_num;
	int cur_rma_addr;
	u32 xfer_len, ds_offset;
	int err;
	u64 loffset;
	u32 dma_size = 0;
	int rma_flag = 0;

	if (unlikely(!qp->conn)) {
		printk(KERN_ALERT PFX "%s: ERROR: qp->conn == NULL\n",
			__func__);
		return -EACCES;
	}

	spin_lock_bh(&qp->rq.lock);
	if (unlikely(pdu->send.msg_id >= qp->rq.next_msg_id)) {
		spin_unlock_bh(&qp->rq.lock);
		printk(KERN_ALERT PFX
			"%s: ERROR: message arrives before recv is posted. "
			"msg_id=%d, rq.next_msg_id=%d\n",
			__func__, pdu->send.msg_id, qp->rq.next_msg_id);
		return -EBADRQC;
	}
	spin_unlock_bh(&qp->rq.lock);

	wr = ibscif_wr_by_msg_id(&qp->rq, pdu->send.msg_id);
	if (unlikely(!wr))
		return -EBADR;

	if (unlikely(pdu->send.msg_length > wr->length))
		return -EMSGSIZE;

	if (unlikely(pdu->send.msg_offset > pdu->send.msg_length))
		return -EINVAL;

	if (unlikely((pdu->hdr.length + pdu->send.msg_offset) > wr->length))
		return -ESPIPE;

	total = 0;

	num_rma_addrs = pdu->send.num_rma_addrs;
	cur_rma_addr = 0;
	rma_offset = pdu->send.rma_addrs[cur_rma_addr].offset;
	rma_length = pdu->send.rma_addrs[cur_rma_addr].length;

	ds_offset = pdu->send.msg_offset;
	ds = wr->ds_list;
	seg_num = 0;
	while ((ds_offset >= ds->length) && (seg_num < wr->num_ds)) {
		ds_offset -= ds->length;
		ds++;
		seg_num++;
	}

	err = 0;
	while (total < pdu->send.msg_length && !err) {
		if (unlikely(seg_num >= wr->num_ds))
			return -EMSGSIZE;

		if (!ds->in_use) {
			mr = ibscif_get_mr(ds->lkey);
			if (unlikely(IS_ERR(mr)))
				return PTR_ERR(mr);
			ds->in_use = 1;
			if (unlikely(mr != ds->mr))
				return -ENXIO;
			if (unlikely(!(mr->access & IB_ACCESS_LOCAL_WRITE)))
				return -EACCES;
		} else
			mr = ds->mr;

		mreg = ibscif_mr_get_mreg(mr, qp->conn);
		if (!mreg)
			return -EACCES;

		while (ds->length > ds_offset) {
			xfer_len = min( ds->length - ds_offset, rma_length );
			if (xfer_len) {
				loffset = mreg->offset + ds->offset + ds_offset;
				dma_size += ibscif_dma_size(xfer_len,
							    rma_offset);

				if ((total + xfer_len >= pdu->send.msg_length)
				     && dma_size)
					rma_flag = SCIF_RMA_SYNC;

				err = scif_readfrom(qp->conn->ep, loffset,
						    xfer_len, rma_offset,
						    rma_flag);
				if (err) {
					printk(KERN_ALERT PFX
						"%s: scif_readfrom (%d bytes) "
						"returns %d\n",
						__func__, xfer_len, err);
					break;
				}

				ds_offset += xfer_len;
				rma_offset += xfer_len;
				rma_length -= xfer_len;
				total += xfer_len;

				if (total >= pdu->send.msg_length)
					break;
			}
			if (rma_length == 0) {
				cur_rma_addr++;
				if (unlikely(cur_rma_addr >= num_rma_addrs))
					return -EMSGSIZE;

				rma_offset =
					pdu->send.rma_addrs[cur_rma_addr].offset;
				rma_length =
					pdu->send.rma_addrs[cur_rma_addr].length;
			}
		}

		seg_num++;
		ds++;
	}

	wr->state = WR_LAST_SEEN;
	wr->sar.rea.opcode = pdu->hdr.opcode;
	wr->sar.rea.last_packet_seq = pdu->hdr.seq_num;
	wr->sar.rea.immediate_data = pdu->send.immed_data;
	wr->sar.rea.final_length = pdu->send.msg_length;

	/* Respond to the initiator with the result */
	wr = ibscif_reserve_wqe(&qp->iq);
	if (unlikely(IS_ERR(wr))) {
		return PTR_ERR(wr);
	}

	memset(&wr->sar, 0, sizeof wr->sar);

	wr->opcode = WR_RMA_RSP;
	wr->state  = WR_WAITING;
	wr->length = 0;
	wr->msg_id = pdu->send.rma_id;
	wr->num_ds = 0;
	wr->rma_rsp.xfer_length = total;
	wr->rma_rsp.error = err;

	ibscif_append_wqe(&qp->iq);
	qp->schedule |= SCHEDULE_RESUME | SCHEDULE_IQ;

	return 0;
}

static int ibscif_process_write_rma(struct ibscif_qp *qp,
				    union ibscif_pdu *pdu,
				    struct sk_buff *skb)
{
	struct ibscif_wr *wr;
	struct ibscif_mr *mr;
	u64 rdma_addr;
	u32 rdma_len;
	struct ibscif_mreg_info *mreg;
	u32 num_rma_addrs;
	u64 rma_offset;
	u32 rma_length;
	u32 total;
	int i;
	int err;
	u64 loffset;
	u32 dma_size = 0;
	int rma_flag = 0;

	if (unlikely(!qp->conn)) {
		printk(KERN_ALERT PFX "%s: ERROR: qp->conn == NULL\n",
			__func__);
		return -EACCES;
	}

	if (unlikely(!(qp->access & IB_ACCESS_REMOTE_WRITE)))
		return -EACCES;

	/* Writes with immediate data consume an rq wqe. */
	if (ibscif_pdu_is_immed(pdu->hdr.opcode)) {
		spin_lock_bh(&qp->rq.lock);
		if (unlikely(pdu->write.msg_id >= qp->rq.next_msg_id)) {
			spin_unlock_bh(&qp->rq.lock);
			return -EBADRQC;
		}
		spin_unlock_bh(&qp->rq.lock);

		wr = ibscif_wr_by_msg_id(&qp->rq, pdu->write.msg_id);
		if (unlikely(!wr))
			return -EBADR;
	}
	else
		wr = NULL;

	rdma_addr = pdu->write.rdma_address;
	rdma_len  = pdu->write.rma_length;
	if (unlikely((rdma_addr + (rdma_len - 1)) < rdma_addr))
		return -EOVERFLOW;

	mr = ibscif_validate_mr(pdu->write.rdma_key,
				rdma_addr, rdma_len, qp->ibqp.pd,
				IB_ACCESS_REMOTE_WRITE);
	if (unlikely(IS_ERR(mr)))
		return PTR_ERR(mr);

	mreg = ibscif_mr_get_mreg(mr, qp->conn);
	if (!mreg)
		return -EACCES;

	total = 0;
	err = 0;
	num_rma_addrs = pdu->write.num_rma_addrs;
	for (i=0; i<num_rma_addrs; i++) {
		rma_offset = pdu->write.rma_addrs[i].offset;
		rma_length = pdu->write.rma_addrs[i].length;

		if (rdma_len < rma_length)
			rma_length = rdma_len;

		if (rma_length == 0)
			continue;

		loffset = mreg->offset + (rdma_addr - mr->addr) + total;
		dma_size += ibscif_dma_size(rma_length, rma_offset);

		if ((i==num_rma_addrs-1) && dma_size)
			rma_flag = SCIF_RMA_SYNC;

		err = scif_readfrom(qp->conn->ep, loffset, rma_length,
				    rma_offset, rma_flag);
		if (err) {
			printk(KERN_ALERT PFX
				"%s: scif_readfrom (%d bytes) returns %d\n",
				__func__, rma_length, err);
			break;
		}

		rdma_len -= rma_length;
		total += rma_length;
	}

	ibscif_put_mr(mr);

	if (wr) {
		wr->sar.rea.final_length = total;
		wr->state = WR_LAST_SEEN;
		wr->sar.rea.opcode = pdu->hdr.opcode;
		wr->sar.rea.last_packet_seq = pdu->hdr.seq_num;
		wr->sar.rea.immediate_data = pdu->write.immed_data;
	}

	/* Respond to the initiator with the result */
	wr = ibscif_reserve_wqe(&qp->iq);
	if (unlikely(IS_ERR(wr))) {
		return PTR_ERR(wr);
	}

	memset(&wr->sar, 0, sizeof wr->sar);

	wr->opcode = WR_RMA_RSP;
	wr->state  = WR_WAITING;
	wr->length = 0;
	wr->msg_id = pdu->write.rma_id;
	wr->num_ds = 0;
	wr->rma_rsp.xfer_length = total;
	wr->rma_rsp.error = err;

	ibscif_append_wqe(&qp->iq);
	qp->schedule |= SCHEDULE_RESUME | SCHEDULE_IQ;

	return 0;
}

static int ibscif_process_read_rma(struct ibscif_qp *qp,
				   union ibscif_pdu *pdu,
				   struct sk_buff *skb)
{
	struct ibscif_wr *wr;
	struct ibscif_mr *mr;
	u64 rdma_addr;
	u32 rdma_len;
	struct ibscif_mreg_info *mreg;
	u32 num_rma_addrs;
	u64 rma_offset;
	u32 rma_length;
	u32 total;
	int i;
	int err;
	u64 loffset;
	u32 dma_size = 0;
	int rma_flag = 0;

	if (unlikely(!qp->conn)) {
		printk(KERN_ALERT PFX "%s: ERROR: qp->conn == NULL\n",
			__func__);
		return -EACCES;
	}

	if (unlikely(!(qp->access & IB_ACCESS_REMOTE_READ)))
		return -EACCES;

	rdma_addr = pdu->read_req.rdma_address;
	rdma_len  = pdu->read_req.rdma_length;
	if (unlikely((rdma_addr + (rdma_len - 1)) < rdma_addr))
		return -EOVERFLOW;

	mr = ibscif_validate_mr(pdu->read_req.rdma_key,
				rdma_addr, rdma_len, qp->ibqp.pd,
				IB_ACCESS_REMOTE_READ);
	if (unlikely(IS_ERR(mr)))
		return PTR_ERR(mr);

	mreg = ibscif_mr_get_mreg(mr, qp->conn);
	if (!mreg)
		return -EACCES;

	total = 0;
	err = 0;
	num_rma_addrs = pdu->read_req.num_rma_addrs;
	for (i=0; i<num_rma_addrs; i++) {
		rma_offset = pdu->read_req.rma_addrs[i].offset;
		rma_length = pdu->read_req.rma_addrs[i].length;

		if (rdma_len < rma_length)
			rma_length = rdma_len;

		if (rma_length == 0)
			continue;

		loffset = mreg->offset + (rdma_addr - mr->addr) + total;
		dma_size += ibscif_dma_size(rma_length, rma_offset);

		if ((i==num_rma_addrs-1) && dma_size)
			rma_flag = SCIF_RMA_SYNC;

		err = scif_writeto(qp->conn->ep, loffset, rma_length,
				   rma_offset, rma_flag);
		if (err) {
			printk(KERN_ALERT PFX
				"%s: scif_writeto (%d bytes) returns %d\n",
				__func__, rma_length, err);
			break;
		}

		rdma_len -= rma_length;
		total += rma_length;
	}

	ibscif_put_mr(mr);

	/* Respond to the initiator with the result */
	wr = ibscif_reserve_wqe(&qp->iq);
	if (unlikely(IS_ERR(wr))) {
		return PTR_ERR(wr);
	}

	memset(&wr->sar, 0, sizeof wr->sar);

	wr->opcode = WR_RMA_RSP;
	wr->state  = WR_WAITING;
	wr->length = 0;
	wr->msg_id = pdu->read_req.rdma_id;
	wr->num_ds = 0;
	wr->rma_rsp.xfer_length = total;
	wr->rma_rsp.error = err;

	ibscif_append_wqe(&qp->iq);
	qp->schedule |= SCHEDULE_RESUME | SCHEDULE_IQ;

	return 0;
}

static int ibscif_process_rma_rsp(struct ibscif_qp *qp,
				  union ibscif_pdu *pdu,
				  struct sk_buff *skb)
{
	struct ibscif_wr *wr;

	wr = ibscif_wr_by_msg_id(&qp->sq, pdu->rma_rsp.rma_id);
	if (unlikely(!wr))
		return -EBADR;
	if (unlikely(!wr->use_rma))
		return -ENOMSG;

	if (wr->opcode == WR_RDMA_READ) {
		/* ibscif_clear_ds_refs() is called in
		 * ibscif_schedule_rx_completions()
		 */
		wr->state = WR_LAST_SEEN;
	}
	else {
		ibscif_clear_ds_refs(wr->ds_list, wr->num_ds);
		wr->state = WR_COMPLETED;
	}

	wr->sar.rea.opcode	    = pdu->hdr.opcode;
	wr->sar.rea.last_packet_seq = pdu->hdr.seq_num;
	wr->sar.rea.final_length    = pdu->rma_rsp.xfer_length;

	return 0;
}

static int ibscif_process_pdu(struct ibscif_qp *qp, union ibscif_pdu *pdu,
			      struct sk_buff *skb)
{
	int err;

	switch (ibscif_pdu_base_type(pdu->hdr.opcode)) {
	case ibscif_op_ud:
		err = ibscif_process_ud(qp, pdu, skb);
		break;
	case ibscif_op_send:
		err = ibscif_process_send(qp, pdu, skb);
		break;
	case ibscif_op_write:
		err = ibscif_process_write(qp, pdu, skb);
		break;
	case ibscif_op_read:
		err = ibscif_process_read(qp, pdu, skb);
		break;
	case ibscif_op_read_rsp:
		err = ibscif_process_read_rsp(qp, pdu, skb);
		break;
	case ibscif_op_comp_swap_rsp:
	case ibscif_op_fetch_add_rsp:
		err = ibscif_process_atomic_rsp(qp, pdu, skb);
		break;
	case ibscif_op_comp_swap:
	case ibscif_op_fetch_add:
		err = ibscif_process_atomic_req(qp, pdu, skb);
		break;
	case ibscif_op_ack:
		/* Handled in piggyback ack processing. */
		err = 0;
		break;
	case ibscif_op_disconnect:
		/* Post send completions before the disconnect flushes
		 * the queues.
		 */
		ibscif_process_ack(qp, &pdu->hdr);
		err = ibscif_process_disconnect(qp, pdu, skb);
		break;
	case ibscif_op_send_rma:
		err = ibscif_process_send_rma(qp, pdu, skb);
		break;
	case ibscif_op_write_rma:
		err = ibscif_process_write_rma(qp, pdu, skb);
		break;
	case ibscif_op_read_rma:
		err = ibscif_process_read_rma(qp, pdu, skb);
		break;
	case ibscif_op_rma_rsp:
		err = ibscif_process_rma_rsp(qp, pdu, skb);
		break;
	default:
		printk(KERN_INFO PFX "Received invalid opcode (%x)\n",
		       ibscif_pdu_base_type(pdu->hdr.opcode));
		err = IBSCIF_REASON_INVALID_OPCODE;
		break;
	}

	if (unlikely(err)) {
		printk(KERN_ALERT PFX "%s: ERROR: err=%d, opcode=%d\n",
			__func__, err, ibscif_pdu_base_type(pdu->hdr.opcode));
		ibscif_protocol_error(qp, IBSCIF_REASON_QP_FATAL);
	}

	return err;
}

static int update_rx_seq_numbers(struct ibscif_qp *qp, union ibscif_pdu *pdu,
				 struct ibscif_rx_state *rx)
{
	u32 seq_num = pdu->hdr.seq_num;

	if (pdu->hdr.opcode == ibscif_op_ack)
		return 0;

	if (seq_num != rx->last_in_seq + 1)
		return 0;

	rx->last_in_seq = seq_num;

	return 1;
}

static void ibscif_process_qp_skb(struct ibscif_qp *qp, struct sk_buff *skb)
{
	union ibscif_pdu *pdu = (union ibscif_pdu *)skb->data;
	struct ibscif_rx_state *rx;
	int err = 0;

	/* Start with no scheduling. */
	qp->schedule = 0;

	rx = ibscif_pdu_is_iq(pdu->hdr.opcode) ?
			&qp->wire.iq.rx : &qp->wire.sq.rx;

	if (ibscif_process_pdu(qp, pdu, skb) == IBSCIF_REASON_INVALID_OPCODE)
		return;

	/* skip ack and seq_num for UD QP */
	if (qp->ibqp.qp_type == IB_QPT_UD) {
		err = ibscif_schedule_rx_completions(qp, 0, rx);
		if (unlikely(err)) {
			printk(KERN_ALERT PFX
				"%s: rx completion error: err=%d, opcode=%d\n",
				__func__, err,
				ibscif_pdu_base_type(pdu->hdr.opcode));
			ibscif_protocol_error(qp, IBSCIF_REASON_QP_FATAL);
		}
		goto done;
	}

	/* Process piggybacked acks. */
	ibscif_process_ack(qp, &pdu->hdr);

	if (update_rx_seq_numbers(qp, pdu, rx)) {
		/* PDU in sequence, schedule/remove completed work requests */
		err = ibscif_schedule_rx_completions(
				qp, ibscif_pdu_is_iq(pdu->hdr.opcode), rx);
		if (unlikely(err)) {
			printk(KERN_ALERT PFX
				"%s: rx completion error: err=%d, opcode=%d\n",
				__func__, err,
				ibscif_pdu_base_type(pdu->hdr.opcode));
			ibscif_protocol_error(qp, IBSCIF_REASON_QP_FATAL);
			goto done;
		}
	}

	/* Generate an ack if forced or if the current window dictates it. */
	if (ibscif_pdu_is_force_ack(pdu->hdr.opcode)) {
		ibscif_send_ack(qp);
	} else if (pdu->hdr.opcode != ibscif_op_ack) {
		u32 window = ibscif_rx_window(rx);
		if (window && (window % (window_size / MIN_WINDOW_SIZE)) == 0)
			ibscif_send_ack(qp);
	}
done:
	/* Run the scheduler if it was requested. */
	if (qp->schedule & SCHEDULE_RESUME) {
		if (qp->schedule & SCHEDULE_SQ)
			ibscif_schedule(&qp->sq);
		if (qp->schedule & SCHEDULE_IQ)
			ibscif_schedule(&qp->iq);
	}

	return;
}

static int ibscif_recv_pkt(struct sk_buff *skb, struct ibscif_dev *dev,
			   scif_epd_t ep, struct ibscif_conn *conn)
{
	union ibscif_pdu *pdu = (union ibscif_pdu *)skb->data;
	struct ibscif_qp *qp = ERR_PTR(-ENOENT);

	if (pdu->hdr.opcode == ibscif_op_close) {
		conn->remote_close = 1;
		goto done_no_qp;
	}
	else if (pdu->hdr.opcode == ibscif_op_reopen) {
		conn->remote_close = 0;
		goto done_no_qp;
	}
	else if (pdu->hdr.opcode == ibscif_op_cm) {
		ibscif_process_cm_skb(skb, conn);
		goto done_no_qp;
	}

	qp = ibscif_get_qp(pdu->hdr.dst_qp);
	if (unlikely(IS_ERR(qp) ||
		     (qp->state != QP_CONNECTED &&
			qp->ibqp.qp_type != IB_QPT_UD) ||
		     (qp->ibqp.qp_num != pdu->hdr.dst_qp) ||
		     (qp->remote_qpn != pdu->hdr.src_qp &&
			qp->ibqp.qp_type != IB_QPT_UD))) {
		/* Disconnect the rogue. */
		ibscif_reflect_disconnect(qp, &pdu->hdr, skb,
					  IBSCIF_REASON_INVALID_QP);
		goto done;
	}

	if (qp->ibqp.qp_type == IB_QPT_UD)
		ibscif_qp_add_ud_conn(qp, conn);

	DEV_STAT(qp->dev, packets_rcvd++);
	DEV_STAT(qp->dev, bytes_rcvd += skb->len);

	ibscif_process_qp_skb(qp, skb);
done:
	if (likely(!IS_ERR(qp)))
		ibscif_put_qp(qp);

done_no_qp:
	kfree_skb(skb);
	return 0;
}

static void ibscif_do_recv(struct ibscif_dev *dev, scif_epd_t ep,
			   struct ibscif_conn *conn)
{
	struct sk_buff *skb;
	union ibscif_pdu *pdu;
	int hdr_size, payload_size, recv_size, pdu_size;
	char *recv_buffer;
	int ret;

	skb = dev_alloc_skb( IBSCIF_MTU );
	if (unlikely(skb==NULL)) {
		printk(KERN_ALERT PFX
			"%s(): fail to allocate skb, exiting\n", __func__);
		return;
	}

	skb->protocol  = __cpu_to_be16(IBSCIF_PACKET_TYPE);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->priority  = TC_PRIO_CONTROL; /* highest defined priority */
	skb->dev       = (void *) dev;

	pdu = (union ibscif_pdu *)skb->data;

	/* get the base header first so the packet size can be determinied */
	recv_size = sizeof(pdu->hdr);
	recv_buffer = (char *)&pdu->hdr;
	while (recv_size) {
		ret = scif_recv(ep, recv_buffer, recv_size,
				blocking_recv ? SCIF_RECV_BLOCK : 0);
		if (ret < 0) {
			printk(KERN_ALERT PFX
				"%s(): fail to receive hdr, ret=%d, "
				"expecting %d\n",
				__func__, ret, (int)recv_size);
			if (ret == -ENOTCONN || ret == -ECONNRESET) {
				if (verbose)
					printk(KERN_INFO PFX
						"%s: ep disconnected by "
						"peer (%d). conn=%p, "
						"local_close=%d\n",
						__func__, ret, conn,
						conn->local_close);
				ibscif_remove_ep( dev, ep );
				ibscif_refresh_pollep_list();
				conn->remote_close = 1;
				if (conn->local_close) {
					ibscif_free_conn(conn);
				}
			}
			goto errout;
		}
		recv_size -= ret;
		recv_buffer += ret;
	}

	hdr_size = pdu->hdr.hdr_size;
	payload_size = pdu->hdr.length;
	pdu_size = hdr_size + payload_size;
	if (unlikely(pdu_size > IBSCIF_MTU)) {
		printk(KERN_ALERT PFX
			"%s(): packet size exceed MTU, size=%d\n",
			__func__, pdu_size);
		goto errout;
	}

	recv_size = pdu_size - sizeof(pdu->hdr);
	recv_buffer = (char *)pdu + sizeof(pdu->hdr);

	/* get the remaining of the packet */
	ret = 0;
	while (recv_size) {
		ret = scif_recv(ep, recv_buffer, recv_size,
				blocking_recv ? SCIF_RECV_BLOCK : 0);

		if (ret < 0) {
			printk(KERN_ALERT PFX
				"%s(): fail to receive data, ret=%d, "
				"expecting %d\n",
				__func__, ret, recv_size);
			break;
		}

		recv_size -= ret;
		recv_buffer += ret;
	}

	if (ret < 0)
		goto errout;

	skb->len       = pdu_size;
	skb->data_len  = payload_size;
	skb->tail     += pdu_size;

	ibscif_recv_pkt(skb, dev, ep, conn);
	return;

errout:
	kfree_skb(skb);
}

#define IBSCIF_MAX_POLL_COUNT (IBSCIF_MAX_DEVICES * 2)
static struct scif_pollepd	poll_eps[IBSCIF_MAX_POLL_COUNT];
static struct ibscif_dev	*poll_devs[IBSCIF_MAX_POLL_COUNT];
static int			poll_types[IBSCIF_MAX_POLL_COUNT];
static struct ibscif_conn	*poll_conns[IBSCIF_MAX_POLL_COUNT];
static struct task_struct	*poll_thread = NULL;
static atomic_t			poll_eps_changed = ATOMIC_INIT(0);
static volatile int		poll_thread_running = 0;

void ibscif_refresh_pollep_list(void)
{
	atomic_set(&poll_eps_changed, 1);
}

static int ibscif_poll_thread(void *unused_arg)
{
	int poll_count = 0;
	int ret;
	int i;
	int busy;
	int idle_count = 0;

	poll_thread_running = 1;
	while (!kthread_should_stop()) {
		if (atomic_xchg(&poll_eps_changed, 0)) {
			poll_count = IBSCIF_MAX_POLL_COUNT;
			ibscif_get_pollep_list(poll_eps, poll_devs,
					       poll_types, poll_conns,
					       &poll_count );
		}

		if (poll_count == 0) {
			schedule();
			continue;
		}

		ret = scif_poll(poll_eps, poll_count, 1000); /* 1s timeout */

		busy = 0;
		if (ret > 0) {
			for (i=0; i<poll_count; i++) {
				if (poll_eps[i].revents & POLLIN) {
					if (poll_types[i] ==
					    IBSCIF_EP_TYPE_LISTEN) {
						ibscif_do_accept(poll_devs[i]);
						busy = 1;
					}
					else {
						ibscif_do_recv(poll_devs[i],
							       poll_eps[i].epd,
							       poll_conns[i]);
						busy = 1;
					}
				}
				else if (poll_eps[i].revents & POLLERR) {
					if (verbose)
						printk(KERN_INFO PFX
							"%s: ep error, "
							"conn=%p.\n",
							__func__,
							poll_conns[i]);
					ibscif_remove_ep(poll_devs[i],
							 poll_eps[i].epd );
					ibscif_refresh_pollep_list();
					/* in most the case, the error is
					 * caused by ep being already closed
					 */
					busy = 1;
				}
				else if (poll_eps[i].revents & POLLHUP) {
					struct ibscif_conn *conn=poll_conns[i];
					if (verbose)
						printk(KERN_INFO PFX
							"%s: ep disconnected "
							"by peer.\n", __func__);
					ibscif_remove_ep(poll_devs[i],
							 poll_eps[i].epd );
					ibscif_refresh_pollep_list();
					if (conn) {
						if (verbose)
							printk(KERN_INFO PFX
							    "%s: conn=%p, "
							    "local_close=%d.\n",
							    __func__, conn,
							    conn->local_close);
						conn->remote_close = 1;
						if (conn->local_close) {
							ibscif_free_conn(conn);
						}
					}
					busy = 1;
				}
			}
		}

		if (busy) {
			idle_count = 0;
		}
		else {
			idle_count++;
			/* close unused endpoint after 60 seconds */
			if (idle_count == 60) {
				if (ibscif_cleanup_idle_conn())
					ibscif_refresh_pollep_list();
				idle_count = 0;
			}
			/* pick up the unprocessed items in the xmit queue */
			if (!skb_queue_empty(&xmit_queue))
				ibscif_dev_queue_xmit(NULL);
			schedule();
		}
	}

	poll_thread_running = 0;
	return 0;
}

void ibscif_protocol_init_pre(void)
{
	skb_queue_head_init(&xmit_queue);
}

void ibscif_protocol_init_post(void)
{
	poll_thread = kthread_run(ibscif_poll_thread, NULL, "ibscif_polld");
}

void ibscif_protocol_cleanup(void)
{
	kthread_stop( poll_thread );

	while (poll_thread_running)
		schedule();
}
