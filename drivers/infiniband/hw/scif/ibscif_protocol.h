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

#ifndef IBSCIF_PROTOCOL_H
#define IBSCIF_PROTOCOL_H

/*
 * Protocol EtherType
 */
#define	IBSCIF_PACKET_TYPE	0x8086

/*
 * Base protocol header version
 */
#define	IBSCIF_PROTOCOL_VER_1	1
#define	IBSCIF_PROTOCOL_VER	IBSCIF_PROTOCOL_VER_1

/*
 * Protocol opcode values - All other values are reserved.
 */
#define ibscif_last_flag		0x4000
#define ibscif_immed_flag		0x2000
#define ibscif_se_flag			0x1000
#define ibscif_force_ack_flag		0x0800
#define ibscif_iq_flag			0x0400

#define	ibscif_op_send			0
#define	ibscif_op_send_last		(ibscif_op_send | ibscif_last_flag)
#define	ibscif_op_send_last_se		(ibscif_op_send | ibscif_last_flag  | ibscif_se_flag)
#define	ibscif_op_send_immed		(ibscif_op_send | ibscif_immed_flag)
#define	ibscif_op_send_immed_se		(ibscif_op_send | ibscif_immed_flag | ibscif_se_flag)

#define	ibscif_op_write			1
#define	ibscif_op_write_last		(ibscif_op_write | ibscif_last_flag)
#define	ibscif_op_write_immed		(ibscif_op_write | ibscif_immed_flag)
#define	ibscif_op_write_immed_se	(ibscif_op_write | ibscif_immed_flag | ibscif_se_flag)

#define	ibscif_op_read			2
#define	ibscif_op_read_rsp		(ibscif_op_read | ibscif_iq_flag)
#define	ibscif_op_read_rsp_last		(ibscif_op_read_rsp | ibscif_last_flag)

#define	ibscif_op_comp_swap		3
#define ibscif_op_comp_swap_rsp		(ibscif_op_comp_swap | ibscif_iq_flag)

#define	ibscif_op_fetch_add		4
#define ibscif_op_fetch_add_rsp		(ibscif_op_fetch_add | ibscif_iq_flag)

#define	ibscif_op_ack			5
#define	ibscif_op_disconnect		6

#define ibscif_op_send_rma		7
#define ibscif_op_send_rma_se		(ibscif_op_send_rma | ibscif_se_flag)
#define ibscif_op_send_rma_immed	(ibscif_op_send_rma | ibscif_immed_flag)
#define ibscif_op_send_rma_immed_se	(ibscif_op_send_rma | ibscif_immed_flag | ibscif_se_flag)

#define ibscif_op_write_rma		8
#define ibscif_op_write_rma_immed	(ibscif_op_write_rma | ibscif_immed_flag)
#define ibscif_op_write_rma_immed_se	(ibscif_op_write_rma | ibscif_immed_flag | ibscif_se_flag)

#define	ibscif_op_read_rma		9
#define ibscif_op_rma_rsp		(10 | ibscif_iq_flag)

#define	ibscif_op_reg			11
#define	ibscif_op_dereg			12

#define ibscif_op_close			13
#define ibscif_op_reopen		14

#define ibscif_op_ud			15
#define ibscif_op_cm			16

#define ibscif_pdu_is_last(op)		(op & ibscif_last_flag)
#define ibscif_pdu_is_immed(op)		(op & ibscif_immed_flag)
#define ibscif_pdu_is_se(op)		(op & ibscif_se_flag)
#define ibscif_pdu_is_force_ack(op)	(op & ibscif_force_ack_flag)
#define ibscif_pdu_is_iq(op)		(op & ibscif_iq_flag)

#define ibscif_pdu_set_last(op)		(op | ibscif_last_flag)
#define ibscif_pdu_set_immed(op)	(op | ibscif_immed_flag)
#define ibscif_pdu_set_se(op)		(op | ibscif_se_flag)
#define ibscif_pdu_set_force_ack(op)	(op | ibscif_force_ack_flag)
#define ibscif_pdu_set_iq(op)		(op | ibscif_iq_flag)

#define ibscif_pdu_base_type(op)	\
	(op & ~(ibscif_last_flag       | \
		ibscif_se_flag         | \
		ibscif_immed_flag      | \
		ibscif_force_ack_flag))

/*
 * Remote address descriptor for SCIF RMA operations
 */
struct rma_addr {
	__be64			offset;
	__be32			length;
	__be32			reserved;
} __attribute__ ((packed));

/*
 * Base header present in every packet
 */
struct base_hdr {
	__be16			opcode;
	__be16			length;
	__be32			dst_qp;
	__be32			src_qp;
	__be32			seq_num;
	__be32			sq_ack_num;
	__be32			iq_ack_num;
	__be16			hdr_size;
	__be16			reserved[3];
} __attribute__ ((packed));

/*
 * UD Header
 */
struct ud_hdr {
	struct base_hdr		hdr;
	__be32			msg_id;
	__be32			msg_length;
	__be32			msg_offset;
	u8			grh[40];
} __attribute__ ((packed));

/*
 * Send Header
 */
struct send_hdr {
	struct base_hdr		hdr;
	__be32			msg_id;
	__be32			msg_length;
	__be32			msg_offset;
	__be32			immed_data;
	__be32			rma_id;		/* RMA */
	__be32			num_rma_addrs;	/* RMA */
	struct rma_addr		rma_addrs[0];	/* RMA */
} __attribute__ ((packed));

/*
 * RDMA Write Header
 */
struct write_hdr {
	struct base_hdr		hdr;
	__be64			rdma_address;
	__be32			rdma_key;
	__be32			immed_data;
	__be32			msg_id;
	__be32			rma_length;	/* RMA */
	__be32			rma_id;		/* RMA */
	__be32			num_rma_addrs;	/* RMA */
	struct rma_addr		rma_addrs[0];	/* RMA */
} __attribute__ ((packed));

/*
 * RDMA Read Request Header
 */
struct read_req_hdr {
	struct base_hdr		hdr;
	__be64			rdma_address;
	__be32			rdma_key;
	__be32			rdma_length;	/* shared with RMA */
	__be32			rdma_id;	/* shared with RMA */
	__be32			num_rma_addrs;	/* RMA */
	struct rma_addr		rma_addrs[0];	/* RMA */
} __attribute__ ((packed));

/*
 * RDMA Read Response Header
 */
struct read_rsp_hdr {
	struct base_hdr		hdr;
	__be32			rdma_offset;
	__be32			rdma_id;
} __attribute__ ((packed));


/*
 * Atomic Compare and Swap Header
 */
struct comp_swap_hdr {
	struct base_hdr		hdr;
	__be64			atomic_address;
	__be64			comp_data;
	__be64			swap_data;
	__be32			atomic_key;
	__be32			atomic_id;
	/* no pad needed */
} __attribute__ ((packed));


/*
 * Atomic Fetch/Add Header
 */
struct fetch_add_hdr {
	struct base_hdr		hdr;
	__be64			atomic_address;
	__be64			add_data;
	__be32			atomic_key;
	__be32			atomic_id;
	/* no pad needed */
} __attribute__ ((packed));

/*
 * Atomic Response Header
 */
struct atomic_rsp_hdr {
	struct base_hdr		hdr;
	__be64			orig_data;
	__be32			atomic_id;
} __attribute__ ((packed));

/*
 * ACK Header
 */
struct ack_hdr {
	struct base_hdr		hdr;
} __attribute__ ((packed));

/*
 * Disconnect Header
 */
struct disconnect_hdr {
	struct base_hdr		hdr;
	__be32			reason;
} __attribute__ ((packed));

/*
 * RMA Response Header
 */
struct rma_rsp_hdr {
	struct base_hdr		hdr;
	__be32			rma_id;
	__be32			xfer_length;
	__be32			error;
} __attribute__ ((packed));

/*
 * MR Reg/Dereg Info Header
 */
struct reg_hdr {
	struct base_hdr		hdr;
	__be64			scif_offset;
	__be64			address;
	__be32			length;
	__be32			rkey;
	__be32			access;
} __attribute__ ((packed));

/*
 * SCIF endpoint close notiffication
 */
struct close_hdr {
	struct base_hdr		hdr;
} __attribute__ ((packed));


#define IBSCIF_CM_REQ	1
#define IBSCIF_CM_REP	2
#define IBSCIF_CM_REJ	3
#define IBSCIF_CM_RTU	4

/*
 * RDMA CM Header
 */

struct cm_hdr {
	struct base_hdr		hdr;
	__be64			req_ctx;
	__be64			rep_ctx;
	__be32			cmd;
	__be16			port;
	__be16			padding;
	__be32			qpn;
	__be32			status;
	__be32			plen;
	u8			pdata[0];
} __attribute__ ((packed));

enum ibscif_reason {	/* Set each value to simplify manual lookup. */

	/* Local Events */
	IBSCIF_REASON_USER_GENERATED	  = 0,
	IBSCIF_REASON_CQ_COMPLETION	  = 1,
	IBSCIF_REASON_NIC_FATAL		  = 2,
	IBSCIF_REASON_NIC_REMOVED	  = 3,

	/* Disconnect Event */
	IBSCIF_REASON_DISCONNECT		  = 4,

	/* CQ Error */
	IBSCIF_REASON_CQ_OVERRUN		  = 5,
	IBSCIF_REASON_CQ_FATAL		  = 6,

	/* QP Errors */
	IBSCIF_REASON_QP_SQ_ERROR	  = 7,
	IBSCIF_REASON_QP_RQ_ERROR	  = 8,
	IBSCIF_REASON_QP_DESTROYED	  = 9,
	IBSCIF_REASON_QP_ERROR		  = 10,
	IBSCIF_REASON_QP_FATAL		  = 11,

	/* Operation Errors */
	IBSCIF_REASON_INVALID_OPCODE	  = 12,
	IBSCIF_REASON_INVALID_LENGTH	  = 13,
	IBSCIF_REASON_INVALID_QP		  = 14,
	IBSCIF_REASON_INVALID_MSG_ID	  = 15,
	IBSCIF_REASON_INVALID_LKEY	  = 16,
	IBSCIF_REASON_INVALID_RDMA_RKEY	  = 17,
	IBSCIF_REASON_INVALID_RDMA_ID	  = 18,
	IBSCIF_REASON_INVALID_ATOMIC_RKEY  = 19,
	IBSCIF_REASON_INVALID_ATOMIC_ID	  = 20,
	IBSCIF_REASON_MAX_IR_EXCEEDED	  = 21,
	IBSCIF_REASON_ACK_TIMEOUT	  = 22,

	/* Protection Errors */
	IBSCIF_REASON_PROTECTION_VIOLATION = 23,
	IBSCIF_REASON_BOUNDS_VIOLATION	  = 24,
	IBSCIF_REASON_ACCESS_VIOLATION	  = 25,
	IBSCIF_REASON_WRAP_ERROR		  = 26
};

union ibscif_pdu {
	struct base_hdr		hdr;
	struct ud_hdr		ud;
	struct send_hdr		send;
	struct write_hdr	write;
	struct read_req_hdr	read_req;
	struct read_rsp_hdr	read_rsp;
	struct comp_swap_hdr	comp_swap;
	struct fetch_add_hdr	fetch_add;
	struct atomic_rsp_hdr	atomic_rsp;
	struct ack_hdr		ack;
	struct disconnect_hdr	disconnect;
	struct rma_rsp_hdr	rma_rsp;
	struct reg_hdr		reg;
	struct close_hdr	close;
	struct cm_hdr		cm;
};

struct ibscif_full_frame {
	union ibscif_pdu	ibscif;
};

static inline int seq_before(u32 seq1, u32 seq2)
{
	return (s32)(seq1 - seq2) < 0;
}

static inline int seq_after(u32 seq1, u32 seq2)
{
	return (s32)(seq2 - seq1) < 0;
}

static inline int seq_between(u32 seq_target, u32 seq_low, u32 seq_high)
{
	return seq_high - seq_low >= seq_target - seq_low;
}

static inline u32 seq_window(u32 earlier, u32 later)
{
	return earlier > later ? ((u32)~0 - earlier) + later : later - earlier;
}

#define ibscif_tx_unacked_window(tx)	seq_window((tx)->last_ack_seq_recvd, (tx)->next_seq - 1)
#define ibscif_rx_window(rx)		seq_window((rx)->last_seq_acked, (rx)->last_in_seq)
#define ibscif_tx_window(tx)		((u32)window_size - ibscif_tx_unacked_window(tx))

#endif /* IBSCIF_PROTOCOL_H */
