#ifndef PACKET_HOOK_H
#define PACKET_HOOK_H

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>

/* 封包資訊結構 */
struct pkt_info {
    __be32 src_ip;      /* 來源 IP */
    __be32 dst_ip;      /* 目的 IP */
    __u16  src_port;    /* 來源 Port */
    __u16  dst_port;    /* 目的 Port */
    __u8   protocol;    /* 協議: TCP / UDP / ICMP */
    __u32  pkt_len;     /* 封包長度 (bytes) */
};

/* 功能1: Hook 註冊 */
int  packet_hook_register(void);

/* 功能2: Hook 卸載 */
void packet_hook_unregister(void);

/* Hook callback */
unsigned int net_guard_hook_fn(void *priv,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state);

/* 解析封包，填入 pkt_info；成功回傳 0，失敗回傳 -1 */
int parse_packet(struct sk_buff *skb, struct pkt_info *info);

#endif /* PACKET_HOOK_H */