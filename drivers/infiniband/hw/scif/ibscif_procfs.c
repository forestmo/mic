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

static int ibscif_stats_show(struct seq_file *m, void *v)
{
	struct ibscif_dev *dev = m->private;

	seq_printf
		(m,
		"%s statistics:\n"
		"    tx_bytes %lu rx_bytes %lu\n"
		"    tx_pkts %lu rx_pkts %lu loopback_pkts %lu\n"
		"    sched_exhaust %lu unavailable %lu\n"
		"    tx_errors %lu duplicates %lu\n"
		"    total wr %lu :\n"
		"        send %lu send_imm %lu write %lu write_imm %lu\n"
		"        recv %lu recv_imm %lu read %lu comp %lu fetch %lu\n"
		"        read_rsp %lu atomic_rsp %lu ud %lu\n"
		"    fast_rdma :\n"
		"        write %lu read %lu unavailable %lu fallback %lu "
		"force_ack %lu tail_write %lu\n",
		dev->ibdev.name,
		DEV_STAT(dev, bytes_sent),
		DEV_STAT(dev, bytes_rcvd),
		DEV_STAT(dev, packets_sent),
		DEV_STAT(dev, packets_rcvd),
		DEV_STAT(dev, loopback),
		DEV_STAT(dev, sched_exhaust),
		DEV_STAT(dev, unavailable),
		DEV_STAT(dev, tx_errors),
		DEV_STAT(dev, duplicates),
		DEV_STAT(dev, wr_opcode[WR_SEND])			+
		DEV_STAT(dev, wr_opcode[WR_SEND_WITH_IMM])		+
		DEV_STAT(dev, wr_opcode[WR_RDMA_WRITE])			+
		DEV_STAT(dev, wr_opcode[WR_RDMA_WRITE_WITH_IMM])	+
		DEV_STAT(dev, recv)					+
		DEV_STAT(dev, recv_imm)					+
		DEV_STAT(dev, wr_opcode[WR_RDMA_READ])			+
		DEV_STAT(dev, wr_opcode[WR_ATOMIC_CMP_AND_SWP])		+
		DEV_STAT(dev, wr_opcode[WR_ATOMIC_FETCH_AND_ADD])	+
		DEV_STAT(dev, wr_opcode[WR_RDMA_READ_RSP])		+
		DEV_STAT(dev, wr_opcode[WR_ATOMIC_RSP]),
		DEV_STAT(dev, wr_opcode[WR_SEND]),
		DEV_STAT(dev, wr_opcode[WR_SEND_WITH_IMM]),
		DEV_STAT(dev, wr_opcode[WR_RDMA_WRITE]),
		DEV_STAT(dev, wr_opcode[WR_RDMA_WRITE_WITH_IMM]),
		DEV_STAT(dev, recv),
		DEV_STAT(dev, recv_imm),
		DEV_STAT(dev, wr_opcode[WR_RDMA_READ]),
		DEV_STAT(dev, wr_opcode[WR_ATOMIC_CMP_AND_SWP]),
		DEV_STAT(dev, wr_opcode[WR_ATOMIC_FETCH_AND_ADD]),
		DEV_STAT(dev, wr_opcode[WR_RDMA_READ_RSP]),
		DEV_STAT(dev, wr_opcode[WR_ATOMIC_RSP]),
		DEV_STAT(dev, wr_opcode[WR_UD]),
		DEV_STAT(dev, fast_rdma_write),
		DEV_STAT(dev, fast_rdma_read),
		DEV_STAT(dev, fast_rdma_unavailable),
		DEV_STAT(dev, fast_rdma_fallback),
		DEV_STAT(dev, fast_rdma_force_ack),
		DEV_STAT(dev, fast_rdma_tail_write)
		);

	return 0;
}

static ssize_t ibscif_stats_write(struct file *file, const char __user *buffer,
				  size_t count, loff_t *ppos)
{
       struct ibscif_dev *dev = PDE_DATA(file_inode(file));
       memset(&dev->stats, 0, sizeof dev->stats);
       return count;
}

static int ibscif_stats_open(struct inode *inode, struct file *file)
{
       return single_open(file, ibscif_stats_show, PDE_DATA(inode));
}

struct file_operations ibscif_fops = {
       .owner = THIS_MODULE,
       .open = ibscif_stats_open,
       .read = seq_read,
       .write = ibscif_stats_write,
       .llseek = seq_lseek,
       .release = seq_release,
};

int ibscif_procfs_add_dev(struct ibscif_dev *dev)
{
       dev->procfs = proc_mkdir(dev->ibdev.name, init_net.proc_net);
       if (!dev->procfs)
	       return -ENOENT;

       if (proc_create_data("stats", S_IRUGO | S_IWUGO, dev->procfs,
			    &ibscif_fops ,dev))
	       return -ENOENT;

       return 0;
}

void ibscif_procfs_remove_dev(struct ibscif_dev *dev)
{
	if (dev->procfs)
		remove_proc_entry("stats", dev->procfs);
	remove_proc_entry(dev->ibdev.name, init_net.proc_net);
}
