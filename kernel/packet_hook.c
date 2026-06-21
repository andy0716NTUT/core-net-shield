/*
 * packet_hook.c - Module 1: Packet Capture Module
 *
 * 功能：
 *   1. Hook 註冊   (nf_register_net_hook)
 *   2. Hook 卸載   (nf_unregister_net_hook)
 *   3. 取得來源 IP
 *   4. 取得目的 IP
 *   5. 取得來源 Port
 *   6. 取得目的 Port
 *   7. 取得 Protocol (TCP / UDP / ICMP)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/inet.h>

#include "packet_hook.h"
#include "detector.h"
#include "logger.h"

/* Netfilter hook 操作結構 */
static struct nf_hook_ops net_guard_nf_ops = {
    .hook     = net_guard_hook_fn,
    .pf       = PF_INET,
    .hooknum  = NF_INET_PRE_ROUTING,   /* 在路由決策前攔截 */
    .priority = NF_IP_PRI_FIRST,
};

/* ------------------------------------------------------------------ */
/* 功能 3-7: 解析封包，填入 pkt_info 結構                              */
/* ------------------------------------------------------------------ */
int parse_packet(struct sk_buff *skb, struct pkt_info *info)
{
    struct iphdr  *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;

    if (!skb)
        return -1;

    iph = ip_hdr(skb);
    if (!iph)
        return -1;

    /* 功能3: 取得來源 IP */
    info->src_ip = iph->saddr;

    /* 功能4: 取得目的 IP */
    info->dst_ip = iph->daddr;

    /* 功能7: 取得 Protocol */
    info->protocol = iph->protocol;

    /* 封包長度 */
    info->pkt_len = ntohs(iph->tot_len);

    /* 功能5 & 6: 取得來源 / 目的 Port (僅 TCP / UDP 有 Port) */
    info->src_port = 0;
    info->dst_port = 0;

    switch (iph->protocol) {
    case IPPROTO_TCP:
        tcph = tcp_hdr(skb);
        if (tcph) {
            /* 功能5: 來源 Port */
            info->src_port = ntohs(tcph->source);
            /* 功能6: 目的 Port */
            info->dst_port = ntohs(tcph->dest);
        }
        break;

    case IPPROTO_UDP:
        udph = udp_hdr(skb);
        if (udph) {
            info->src_port = ntohs(udph->source);
            info->dst_port = ntohs(udph->dest);
        }
        break;

    case IPPROTO_ICMP:
        /* ICMP 沒有 Port，保持 0 */
        break;

    default:
        /* 不處理其他協議 */
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Netfilter Hook 回呼函式                                              */
/* ------------------------------------------------------------------ */
unsigned int net_guard_hook_fn(void *priv,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state)
{
    struct pkt_info info;

    /* 解析失敗：放行，不處理 */
    if (parse_packet(skb, &info) < 0)
        return NF_ACCEPT;

    /* 傳送給 Detection Module 進行分析 */
    detect_packet(&info);

    /* 永遠放行：封鎖由 iptables (autoblock.sh) 負責 */
    return NF_ACCEPT;
}

/* ------------------------------------------------------------------ */
/* 功能1: Hook 註冊                                                     */
/* ------------------------------------------------------------------ */
int packet_hook_register(void)
{
    int ret;

    ret = nf_register_net_hook(&init_net, &net_guard_nf_ops);
    if (ret < 0) {
        pr_err("net_guard: nf_register_net_hook 失敗，錯誤碼 %d\n", ret);
        return ret;
    }

    pr_info("net_guard: Netfilter Hook 已註冊 (PRE_ROUTING)\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* 功能2: Hook 卸載                                                     */
/* ------------------------------------------------------------------ */
void packet_hook_unregister(void)
{
    nf_unregister_net_hook(&init_net, &net_guard_nf_ops);
    pr_info("net_guard: Netfilter Hook 已卸載\n");
}