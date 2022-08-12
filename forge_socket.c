#include <linux/module.h>   /* Needed by all modules */
#include <linux/kernel.h>   /* Needed for KERN_INFO */
#include <net/protocol.h>
#include <linux/file.h>
#include <linux/jiffies.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/tcp.h>
#include <linux/version.h>
#include <net/inet_connection_sock.h>
#include <net/tcp.h>
#include <net/tcp_states.h>
#include <net/inet_common.h>
#include <net/inet_timewait_sock.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/route.h>
#include <linux/uaccess.h>
#include "forge_socket.h"



struct proto forge_prot;
struct proto_ops inet_forge_ops;
static struct inet_protosw forge_sw = {
	.type       = SOCK_FORGE,
	.protocol   = IPPROTO_TCP,
	.prot       = &forge_prot,
	.ops        = &inet_forge_ops,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
	.no_check   = 0,
#endif
	.flags      = INET_PROTOSW_ICSK,
};


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
/*
struct tcp_congestion_ops tcp_init_congestion_ops  = {
	.name		= "",
	.owner		= THIS_MODULE,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
        .min_cwnd       = tcp_reno_min_cwnd,
};
*/
//extern struct tcp_congestion_ops tcp_init_congestion_ops;
#endif

/* This is a copy of inet_listen, but uses SOCK_FORGE instead of SOCK_STREAM
   This allows us to listen on SOCK_FORGE sockets.
*/
int inet_forge_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int err;

	lock_sock(sk);

	err = -EINVAL;
	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_FORGE)
		goto out;

	old_state = sk->sk_state;
	if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
		goto out;

	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	if (old_state != TCP_LISTEN) {
		err = inet_csk_listen_start(sk, backlog);
		if (err)
			goto out;
	}
	sk->sk_max_ack_backlog = backlog;
	err = 0;

out:
	release_sock(sk);
	return err;
}


int __init forge_init(void)
{
	int rc = -EINVAL;
	printk(KERN_INFO "Loaded forge_socket\n");

	/* functions for a listening socket of type SOCK_FORGE */
	memcpy(&inet_forge_ops, &inet_stream_ops, sizeof(inet_forge_ops));
	inet_forge_ops.listen = inet_forge_listen;
	inet_forge_ops.getsockopt = forge_getsockopt_socket;


	/* Not all tcp_prot's memebers were exported from the kernel,
	   so we use this hack to grab them from the exported tcp_prot struct,
	   and fill in our own.
	*/
	memcpy(&forge_prot, &tcp_prot, sizeof(forge_prot));
	strncpy(forge_prot.name, "FORGE", sizeof(forge_prot.name));
	forge_prot.owner = THIS_MODULE;
	forge_prot.getsockopt = forge_getsockopt;
	forge_prot.setsockopt = forge_setsockopt;

	/* proto_register will only alloc twsk_prot and rsk_prot if they are
	   null no sense in allocing more space - we can just use TCP's, since
	   we are effecitvely just a TCP socket
	  (though it will alloc .slab even if non-null - we let it).
	*/
	rc = proto_register(&forge_prot, 1);
	if (rc) {
		printk(KERN_CRIT "forge_init: Cannot register protocol"
			   "(already loaded?)\n");
		return rc;
	}

	inet_register_protosw(&forge_sw);

	return 0;
}

void __exit forge_exit(void)
{
	/* Currently, we're pointing to tcp_prot's twsk_prot and rsk_prot
	   and a call to proto_unregister will free these if non-null.
	   (We did allocate our own slab though, so proto_unregister will free
	    that for us)
	*/
	forge_prot.rsk_prot = NULL;
	forge_prot.twsk_prot = NULL;

	inet_unregister_protosw(&forge_sw);
	proto_unregister(&forge_prot);

	printk(KERN_INFO "forge_socket: unloaded\n");
}


int forge_getsockopt(struct sock *sk, int level, int optname,
		char __user *optval, int __user *optlen)
{
	struct tcp_state ret;

	if (optname == TCP_STATE) {
		if (!capable(CAP_NET_RAW))
			return -EACCES;

        memset(&ret, 0, sizeof(ret));

		ret.ack     = tcp_sk(sk)->rcv_nxt;
		ret.seq     = tcp_sk(sk)->snd_nxt;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		ret.src_ip  = inet_sk(sk)->rcv_saddr;
		ret.dst_ip  = inet_sk(sk)->daddr;
		ret.sport   = inet_sk(sk)->sport;
		ret.dport   = inet_sk(sk)->dport;
#else
		ret.src_ip  = inet_sk(sk)->inet_rcv_saddr;
		ret.dst_ip  = inet_sk(sk)->inet_daddr;
		ret.sport   = inet_sk(sk)->inet_sport;
		ret.dport   = inet_sk(sk)->inet_dport;
		ret.inet_ttl = inet_sk(sk)->uc_ttl;
#endif

		ret.snd_una = tcp_sk(sk)->snd_una;
		ret.snd_wnd = tcp_sk(sk)->snd_wnd;
		ret.rcv_wnd = tcp_sk(sk)->rcv_wnd;

		ret.tstamp_ok  = tcp_sk(sk)->rx_opt.tstamp_ok;
		ret.ecn_ok     = ((tcp_sk(sk)->ecn_flags & TCP_ECN_OK) != 0);
		ret.sack_ok    = tcp_sk(sk)->rx_opt.sack_ok;
		ret.wscale_ok  = tcp_sk(sk)->rx_opt.wscale_ok;
		ret.snd_wscale = tcp_sk(sk)->rx_opt.snd_wscale;
		ret.rcv_wscale = tcp_sk(sk)->rx_opt.rcv_wscale;

		ret.mss_clamp  = tcp_sk(sk)->advmss;

		/* TODO: check optlen == sizeof(ret),
		   otherwise only write optlen bytes!
		*/
		if (put_user(sizeof(ret), optlen))
			return -EFAULT;
		if (copy_to_user(optval, &ret, sizeof(ret)))
			return -EFAULT;
		return 0;
	}
	return tcp_getsockopt(sk, level, optname, optval, optlen);
}
EXPORT_SYMBOL(forge_getsockopt);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
int forge_setsockopt(struct sock *sk, int level, int optname,
		char __user *optval, unsigned int optlen)
#else
int forge_setsockopt(struct sock *sk, int level, int optname,
		sockptr_t optval, unsigned int optlen)
#endif
{
	if (optname == TCP_STATE) {
		struct tcp_state st;
		struct inet_connection_sock *icsk;
		struct tcp_sock *tp;

		if (!capable(CAP_NET_RAW))
			return -EACCES;


#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
		if (copy_from_user(&st, (struct tcp_state __user *)optval, sizeof(st)))
#else
		if (copy_from_sockptr(&st, optval, sizeof(st)))

#endif
			return -EFAULT;

		/* from syn_recv: */
		icsk = inet_csk(sk);
		tp = tcp_sk(sk);
        /* TODO: Support kernel > 3.3 which doesn't do inet_sk() */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		inet_sk(sk)->daddr = st.dst_ip;
		inet_sk(sk)->rcv_saddr = st.src_ip;
		inet_sk(sk)->saddr = st.src_ip;
		inet_sk(sk)->id = tp->write_seq ^ jiffies;
#else
		inet_sk(sk)->inet_daddr = st.dst_ip;
		inet_sk(sk)->inet_rcv_saddr = st.src_ip;
		inet_sk(sk)->inet_saddr = st.src_ip;
		inet_sk(sk)->inet_id = tp->write_seq ^ jiffies;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
		inet_sk(sk)->opt = NULL;	/* TODO: support Ip options */
#else
        inet_sk(sk)->inet_opt = NULL;
#endif

		inet_sk(sk)->mc_ttl = 1;    /* TODO: add multicast support */

		icsk->icsk_ext_hdr_len = 0;

		tcp_mtup_init(sk);
		tp->advmss = 1460;  // Hack...
		if (tp->rx_opt.user_mss && tp->rx_opt.user_mss < tp->advmss)
			tp->advmss = tp->rx_opt.user_mss;

		/* from inet_csk_forge: */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		inet_sk(sk)->dport = st.dport;
		inet_sk(sk)->num = ntohs(st.sport);
		inet_sk(sk)->sport = st.sport;
#else
		inet_sk(sk)->inet_dport = st.dport;
		inet_sk(sk)->inet_num = ntohs(st.sport);
		inet_sk(sk)->inet_sport = st.sport;
#endif
		//sk->sk_write_space = sk_stream_write_space;

		inet_csk(sk)->icsk_retransmits = 0;
		inet_csk(sk)->icsk_backoff = 0;
		inet_csk(sk)->icsk_probes_out = 0;
		/* Deinitialize accept_queue to trap illegal accesses. */
		memset(&icsk->icsk_accept_queue, 0,
			   sizeof(icsk->icsk_accept_queue));


		/* from tcp_create_openreq_child: */
		tp->pred_flags = 0;
		tp->rcv_wup = tp->copied_seq = tp->rcv_nxt = st.ack;

		tp->snd_sml = tp->snd_nxt = tp->snd_up = st.seq;
		/* + tcp_s_data_size(oldtp) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
        tcp_prequeue_init(tp);
		tp->srtt = 0;
		tp->mdev = TCP_TIMEOUT_INIT;
#else
		tp->srtt_us = 0;
		tp->mdev_us = TCP_TIMEOUT_INIT;
#endif
		icsk->icsk_rto = TCP_TIMEOUT_INIT;

		tp->packets_out = 0;
		tp->retrans_out = 0;
		tp->sacked_out = 0;
		//tp->fackets_out = 0;
		tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;

		tp->snd_cwnd = 2;
		tp->snd_cwnd_cnt = 0;

		// For some reason, tcp_init_congestion_ops doesn't reach us
		// so we can just call tcp_init_sock() to set it instead.
		//icsk->icsk_ca_ops = &tcp_init_congestion_ops;
		icsk->icsk_ca_ops = NULL;
		tcp_init_sock(sk);

		tcp_set_ca_state(sk, TCP_CA_Open);
		//tcp_init_xmit_timers(sk);	// No longer exported >= 4.3, but is actually called in tcp_init_sock() above
		//skb_queue_head_init(&tp->out_of_order_queue);
		tp->write_seq = tp->pushed_seq = tp->snd_nxt;

		tp->rx_opt.saw_tstamp = 0;

		tp->rx_opt.dsack = 0;
		tp->rx_opt.num_sacks = 0;

		tp->urg_data = 0;

		tp->rx_opt.tstamp_ok = st.tstamp_ok ? 1 : 0;
		tp->rx_opt.sack_ok = st.sack_ok;
		/* TODO: support fack ? */

		tp->window_clamp = 65535 << 14; /* set to max for now */
		tp->rcv_ssthresh = tp->rcv_wnd = st.rcv_wnd << st.rcv_wscale;

		tp->rx_opt.wscale_ok = st.wscale_ok;
		if (tp->rx_opt.wscale_ok) {
			tp->rx_opt.snd_wscale = st.snd_wscale;
			tp->rx_opt.rcv_wscale = st.rcv_wscale;
		} else {
			tp->rx_opt.snd_wscale = tp->rx_opt.rcv_wscale = 0;
			tp->window_clamp = min(tp->window_clamp, 65535U);
		}

		tp->snd_wnd = st.snd_wnd << tp->rx_opt.snd_wscale;
		tp->max_window = tp->snd_wnd;

		if (tp->rx_opt.tstamp_ok) {
			tp->rx_opt.ts_recent = st.ts_recent;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
			//The get_seconds() function is deprecated as it truncates
			// the timestamp to 32 bits. Change to either ktime_get_seconds()
			// or ktime_get_real_seconds()
			tp->rx_opt.ts_recent_stamp = get_seconds();
#else
			tp->rx_opt.ts_recent_stamp = ktime_get_real_seconds();
# endif
			/* We want get_seconds() + ts_offset == st->ts_val.
			*/
			//tp->rx_opt.ts_offset = st->ts_val - tcp_time_stamp;
			//tp->rx_opt.rcv_tsval = st.ts_val;
			//tp->rx_opt.rcv_tsecr = st.ts_val;
			tp->tsoffset = st.ts_val - ((__u32)(jiffies));

			tp->advmss -= TCPOLEN_TSTAMP_ALIGNED;
			tp->tcp_header_len = sizeof(struct tcphdr);
			tp->tcp_header_len += TCPOLEN_TSTAMP_ALIGNED;
		} else {
			tp->rx_opt.ts_recent_stamp = 0;
			tp->tcp_header_len = sizeof(struct tcphdr);
			tp->rx_opt.rcv_tsval = 0;
		}

		tp->rx_opt.mss_clamp = st.mss_clamp;
		tp->ecn_flags = st.ecn_ok ? TCP_ECN_OK : 0;

		sk->sk_socket->state = SS_CONNECTED;

		/* from recv_ack: */
		tp->copied_seq = tp->rcv_nxt;
		smp_mb();
		tcp_set_state(sk, TCP_ESTABLISHED);
		sk->sk_state_change(sk);

		tp->snd_una = tp->snd_up = st.snd_una;
		tcp_init_wl(tp, st.ack);

		/* TODO(swolchok): use a real RTT measurement. */
		/* TODO(ewust): use exported functions to do this */
		/* tcp_valid_rtt_meas(sk, msecs_to_jiffies(10));
		tcp_ack_update_rtt(sk, 0, 0); */

		icsk->icsk_af_ops->rebuild_header(sk);

		/* tcp_init_metrics(sk);
		tcp_init_congestion_control(sk);*/

		if (icsk->icsk_ca_ops->init)
			icsk->icsk_ca_ops->init(sk);

		tp->lsndtime = jiffies;

		tcp_initialize_rcv_mss(sk);
		/*tcp_init_buffer_space(sk);*/
		tcp_fast_path_on(tp);

		/* If user did not call bind on this socket,
		   we'll have to do this:
		*/
		/*inet_csk_get_port(sk, st->sport);*/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		__inet_hash_nolisten(sk);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
		__inet_hash_nolisten(sk, NULL);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 191)
		inet_ehash_nolisten(sk, NULL);
#else
		// https://www.spinics.net/lists/kernel/msg4334811.html
		// bool inet_ehash_nolisten(struct sock *sk, struct sock *osk,
		// 	 bool *found_dup_sk);
		inet_ehash_nolisten(sk, NULL, NULL);
#endif

		/* uc_ttl is at least as old as 2.6.17, maybe older.
		 * TODO: test whether it works properly prior to 4.0,
		 * which is the farthest back I've tested.
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
		/* Not all permissible s16 values are valid TTL
		 * values; any negative number is changed
		 * to -1 (so that the driver will use the
		 * default TTL) and anything larger than 255
		 * is truncated to fit in 8 bits.  (A TTL of
		 * zero is permitted, as a way to test that
		 * packets are dropped correctly, but otherwise
		 * doesn't usually make sense.)
		 */
		if (st.inet_ttl < 0) {
		    inet_sk(sk)->uc_ttl = -1;
		}
		else if (st.inet_ttl > 255) {
		    inet_sk(sk)->uc_ttl = 255;
		}
		else {
		    inet_sk(sk)->uc_ttl = st.inet_ttl;
		}
#endif

		return 0;
	}

	return tcp_setsockopt(sk, level, optname, optval, optlen);
}
EXPORT_SYMBOL(forge_setsockopt);


module_init(forge_init);
module_exit(forge_exit);

/* Originally adapted from Scott Wolchok's kernel patch. */
MODULE_AUTHOR("Eric Wustrow,"
			  "Scott Wolchok");
MODULE_DESCRIPTION("Creates TCP sockets with arbitrary TCP/IP state "
				   "(src, dst) (ports, seq, ack etc)");
MODULE_LICENSE("GPL");

