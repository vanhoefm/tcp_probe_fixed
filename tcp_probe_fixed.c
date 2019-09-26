/*
 * tcpprobe - Observe the TCP flow with kprobes.
 *
 * The idea for this came from Werner Almesberger's umlsim
 * Copyright (C) 2004, Stephen Hemminger <shemminger@osdl.org>
 * Copyright (C) 2013, Timo Dörr <timo@latecrew.de> (minor fixes and
 *  changes)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/circ_buf.h>
#include <net/net_namespace.h>
#include <net/net_namespace.h>
#include <linux/version.h>

#include <net/tcp.h>



/* maximum amount of probes to be buffered before forced-output
 * to userspace
 */
// TODO make module parameter
#define EVENT_BUF 1

MODULE_AUTHOR("A human, not a dog!");
MODULE_DESCRIPTION("TCP-Window Inspector");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.1");

static int port __read_mostly = 0;
MODULE_PARM_DESC(port, "Port to match (0=all)");
module_param(port, int, 0);

static unsigned int bufsize __read_mostly = 4096;
MODULE_PARM_DESC(bufsize, "Log buffer size in packets (4096)");
module_param(bufsize, uint, 0);

static int full __read_mostly;
MODULE_PARM_DESC(full, "Full log (1=every ack packet received,  0=only cwnd changes)");
module_param(full, int, 0);

static const char procname[] = "tcpprobe";

enum LogType {
	LogType_Rx,
	LogType_Tx,
	LogType_Stats
};

const char *logtype2str(enum LogType type)
{
	switch (type) {
	case LogType_Rx:    return "RECV";
	case LogType_Tx:    return "XMIT";
	case LogType_Stats: return "INFO";
	}

	return "??";
}

struct tcp_log {
	ktime_t 	tstamp;
	enum LogType	type;
	__be32		saddr, daddr;
	__be16		sport, dport;
	u16		length;
	u32		snd_nxt;
	u32		snd_una;
	u32		snd_wnd;
	u32		rcv_wnd;
	u32		packets_out;
	u32		snd_cwnd;
	u32		ssthresh;
	u32		icsk_rto;
	u32		srtt;
};

static struct {
	spinlock_t	producer_lock, consumer_lock;
	wait_queue_head_t wait;
	ktime_t		start;
	u32		lastcwnd;

	unsigned long	head, tail;
	struct tcp_log	*log;
} tcp_probe;

/* copies the probe data from the socket */
static inline void copy_to_tcp_probe(const struct sock *sk, const struct sk_buff *skb, struct tcp_log *p, enum LogType type) {

	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *inet = inet_sk(sk);
	
	p->type = type;
	p->tstamp = ktime_get();
	p->saddr = inet->inet_saddr;
	p->sport = inet->inet_sport;
	p->daddr = inet->inet_daddr;
	p->dport = inet->inet_dport;
	p->snd_nxt = tp->snd_nxt;           // SN of the next segment to be sent (*)
	p->snd_una = tp->snd_una;           // oldest unacknowledged SN (*)
	p->snd_cwnd = tp->snd_cwnd;
	p->packets_out = tp->packets_out;   // Packets which are "in flight"
	p->snd_wnd = tp->snd_wnd;           // Size of the send window (*)
	p->rcv_wnd = tp->rcv_wnd;
	p->ssthresh = tcp_current_ssthresh(sk);
	p->icsk_rto = inet_csk(sk)->icsk_rto;	// Retransmit timeout (used to determine slow-restart timeout)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,14,0)
	p->srtt = tp->srtt >> 3;
#else
	p->srtt = tp->srtt_us >> 3;
#endif

	p->length = skb == NULL ? 0 : skb->len;
	
	return;	
}

static int tcpprobe_sprint(const struct tcp_log *p, char *tbuf, int n)
{
	struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), tcp_probe.start));

	unsigned int unacked_data      = p->snd_nxt - p->snd_una;
	unsigned int window_space_left = p->snd_wnd - unacked_data;
	int ret = scnprintf(tbuf, n,
			"[%4lu.%09lu] %4s: %pI4:%u %pI4:%u | CWND %3u/%3u | UNACK %6u/%6u - LEFT %u | rcv_wnd=%u ssthresh=%u srtt=%u rto=%u\n",
			(unsigned long) tv.tv_sec,
			(unsigned long) tv.tv_nsec,
			logtype2str(p->type),
			&p->saddr, ntohs(p->sport),
			&p->daddr, ntohs(p->dport),
			p->packets_out, p->snd_cwnd,		// CONG
			unacked_data, p->snd_wnd,		// UNACK
			window_space_left,
			p->rcv_wnd, p->ssthresh, p->srtt,
			p->icsk_rto);

	return ret;
}

static inline void tcpprobe_add_probe(const struct sock *sk, const struct sk_buff *skb, int type) {
	
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *inet = inet_sk(sk);
	
	struct tcphdr *th;
	unsigned int head,tail;

	u32 sport, dport;

	if (0 && skb != NULL) {
		th = tcp_hdr(skb);
		dport =	ntohs(th->dest);
		sport =	ntohs(th->source);
	} else {
		sport = ntohs(inet->inet_sport);
		dport = ntohs(inet->inet_dport);
	}

	if ((port == 0 || sport == port || dport == port) &&
	    (full || tp->snd_cwnd != tcp_probe.lastcwnd)) {
		
		spin_lock(&tcp_probe.producer_lock);

		// reset timer
		if (tcp_probe.start.tv64 == 0)
			tcp_probe.start = ktime_get();

		head = tcp_probe.head;
		tail = ACCESS_ONCE(tcp_probe.tail);

		if (CIRC_SPACE(head, tail, bufsize) >= 1) {
			struct tcp_log *p = tcp_probe.log + tcp_probe.head;
			copy_to_tcp_probe (sk, skb, p, type);

			tcp_probe.head = (head + 1) & (bufsize - 1);

			wake_up(&tcp_probe.wait);
		}
		tcp_probe.lastcwnd = tp->snd_cwnd;
		spin_unlock(&tcp_probe.producer_lock);
	}

	return;
}

/*
 * Hook inserted to be called before each receive packet.
 * Note: arguments must match tcp_rcv_established()!
 */
static int jtcp_rcv_established(struct sock *sk, struct sk_buff *skb, struct tcphdr *th, unsigned len)
{
	tcpprobe_add_probe (sk, skb, LogType_Rx);
	jprobe_return();
	return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,17,0)
static int jtcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask)
{
	tcpprobe_add_probe (sk, skb, LogType_Tx);
	jprobe_return();
	return 0;
}
#else
static void jtcp_rate_skb_sent(struct sock *sk, struct sk_buff *skb)
{
	tcpprobe_add_probe (sk, skb, LogType_Tx);
	jprobe_return();
}
#endif

static struct jprobe jp_rx = {
	.kp.symbol_name = "tcp_rcv_established",
	.entry = jtcp_rcv_established
};
static struct jprobe jp_tx = {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,17,0)
	.kp.symbol_name = "tcp_transmit_skb",
	.entry = jtcp_transmit_skb
#else
	.kp.symbol_name = "tcp_rate_skb_sent",
	.entry = jtcp_rate_skb_sent
#endif
};
static struct jprobe *tcp_jprobe[] = {
	&jp_rx,
	&jp_tx,
};


struct rethandler_event_data {
	struct sock *sk;
	struct sk_buff *skb;
};

static int entry_hander_tcp_event_new_data_sent(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct rethandler_event_data *data = (struct rethandler_event_data *)ri->data;

	// FIXME: this is x64 specific
	data->sk = (struct sock *)regs->di;
	data->skb = (struct sk_buff *)regs->si;

	return 0;
}

static int ret_handler_tcp_event_new_data_sent(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct rethandler_event_data *data = (struct rethandler_event_data *)ri->data;

	tcpprobe_add_probe (data->sk, data->skb, LogType_Stats);	

	return 0;
}

static struct kretprobe retp_event = {
	.handler	= ret_handler_tcp_event_new_data_sent,
	.entry_handler	= entry_hander_tcp_event_new_data_sent,
	.data_size	= sizeof(struct rethandler_event_data),
	.maxactive	= 20,
	.kp.symbol_name	= "tcp_event_new_data_sent"
};
static struct kretprobe *tcp_kprobe[] = {
	&retp_event
};

static int tcpprobe_open(struct inode * inode, struct file * file)
{
	/* Reset (empty) log */
	spin_lock(&tcp_probe.producer_lock);
	spin_lock(&tcp_probe.consumer_lock);
	tcp_probe.head = tcp_probe.tail = 0;

	// reset the timer
	tcp_probe.start.tv64 = 0;
	spin_unlock(&tcp_probe.consumer_lock);
	spin_unlock(&tcp_probe.producer_lock);

	return 0;
}
static ssize_t tcpprobe_read(struct file *file, char __user *buf,
			     size_t len, loff_t *ppos)
{
	int error = 0;
	size_t cnt = 0;
	
	int eventbuf = EVENT_BUF;

	if (!buf)
		return -EINVAL;

	while (eventbuf > 0 && cnt < len) {
		char tbuf[512];
		int width = 0;
		unsigned long head, tail;
		
		error = wait_event_interruptible (
				tcp_probe.wait,
				CIRC_CNT(ACCESS_ONCE(tcp_probe.head), tcp_probe.tail, bufsize) > 0
		);

		if (error)
			break;

		spin_lock_bh(&tcp_probe.consumer_lock);

		head = ACCESS_ONCE(tcp_probe.head);
		tail = tcp_probe.tail;

		/* re-check condition as head could have
		   changed before the lock was acquired */	
		if(CIRC_CNT(head, tail, bufsize) > 0) {
			struct tcp_log *p;

			p = tcp_probe.log + tcp_probe.tail;
	
			if (cnt + width < len)
				tcp_probe.tail = (tail + 1) & (bufsize - 1);
		
			width = tcpprobe_sprint(p, tbuf, sizeof(tbuf));
		}

		spin_unlock_bh(&tcp_probe.consumer_lock);
		
		// if record greater than space available
		//   return partial buffer (so far) 
		if (cnt + width >= len) {
			printk("cnt +width is >= len, breaking!\n");
			break;
		}
		
		if (copy_to_user(buf + cnt, tbuf, width)) {
		//if (copy_to_user(buf, tbuf, width)) {
			printk("error copying to user!\n");
			return -EFAULT;
		}
		eventbuf--;
		cnt += width;
	}
	return cnt == 0 ? error : cnt;
}

static int tcpprobe_release(struct inode *inode, struct file *file) {
	
	return 0;
}

static const struct file_operations tcpprobe_fops = {
	.owner	 = THIS_MODULE,
	.open	 = tcpprobe_open,
	.release = tcpprobe_release,
	.read    = tcpprobe_read,
	.llseek  = noop_llseek,
};

static __init int tcpprobe_init(void)
{
	int ret = -ENOMEM;

	init_waitqueue_head(&tcp_probe.wait);
	spin_lock_init(&tcp_probe.producer_lock);
	spin_lock_init(&tcp_probe.consumer_lock);

	if (bufsize == 0)
		return -EINVAL;

	bufsize = roundup_pow_of_two(bufsize);

	tcp_probe.log = kcalloc(bufsize, sizeof(struct tcp_log), GFP_KERNEL);
	if (!tcp_probe.log)
		goto err0;

	if (!proc_create(procname, S_IRUSR, init_net.proc_net, &tcpprobe_fops))
		goto err0;

	ret = register_jprobes(tcp_jprobe, ARRAY_SIZE(tcp_jprobe));
	if (ret) goto err1;
	ret = register_kretprobes(tcp_kprobe, ARRAY_SIZE(tcp_kprobe));
	if (ret) {
		unregister_jprobes(tcp_jprobe, ARRAY_SIZE(tcp_jprobe));
		goto err1;
	}

	pr_info("TCP probe registered (port=%d) bufsize=%u\n", port, bufsize);
	return 0;
 err1:
	remove_proc_entry(procname, init_net.proc_net);
 err0:
	kfree(tcp_probe.log);
	return ret;
}
module_init(tcpprobe_init);

static __exit void tcpprobe_exit(void)
{
	remove_proc_entry(procname, init_net.proc_net);
	unregister_kretprobes(tcp_kprobe, ARRAY_SIZE(tcp_kprobe));
	unregister_jprobes(tcp_jprobe, ARRAY_SIZE(tcp_jprobe));
	kfree(tcp_probe.log);
}
module_exit(tcpprobe_exit);

