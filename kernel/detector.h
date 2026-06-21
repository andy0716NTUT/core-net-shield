#ifndef DETECTOR_H
#define DETECTOR_H

#include <linux/types.h>
#include "packet_hook.h"

/* ------------------------------------------------------------------ */
/* Port Scan 偵測參數                                                   */
/* ------------------------------------------------------------------ */
#define PORTSCAN_TIME_WINDOW_SEC   10   /* 功能9:  時間窗口 (秒) */
#define PORTSCAN_PORT_THRESHOLD    20   /* 功能10: 觸發閾值 (不同 Port 數) */
#define MAX_TRACK_IPS             256   /* 最多同時追蹤的 IP 數量 */
#define MAX_PORTS_PER_IP          64    /* 每個 IP 最多記錄的 Port 數 */

/* ------------------------------------------------------------------ */
/* DDoS / 高流量偵測參數                                                */
/* ------------------------------------------------------------------ */
#define DDOS_TIME_WINDOW_SEC        1   /* 功能12: 時間統計窗口 (秒) */
#define DDOS_PACKET_THRESHOLD    1000   /* 功能14: 封包數閾值 (packets/sec) */

/* ------------------------------------------------------------------ */
/* Port Scan 追蹤表項目                                                  */
/* ------------------------------------------------------------------ */
struct port_scan_entry {
    __be32   src_ip;                        /* 追蹤的來源 IP */
    __u16    ports[MAX_PORTS_PER_IP];       /* 功能8: 連過的 Port 清單 */
    int      port_count;                    /* 已記錄的不同 Port 數 */
    ktime_t  window_start;                  /* 功能9: 時間窗口起始時間 */
    int      used;                          /* 此槽位是否使用中 */
};

/* ------------------------------------------------------------------ */
/* DDoS 追蹤表項目                                                       */
/* ------------------------------------------------------------------ */
struct ddos_entry {
    __be32   src_ip;            /* 追蹤的來源 IP */
    __u64    pkt_count;         /* 功能11: 封包計數器 */
    __u64    byte_count;        /* 功能13: 流量統計 (bytes) */
    ktime_t  window_start;      /* 功能12: 時間統計起始 */
    int      used;
};

/* ------------------------------------------------------------------ */
/* 公開介面                                                              */
/* ------------------------------------------------------------------ */

/* 初始化偵測模組 */
int  detector_init(void);

/* 清理偵測模組 */
void detector_exit(void);

/* 主要入口：被 packet_hook.c 呼叫 */
void detect_packet(const struct pkt_info *info);

/* 功能8:  統計 IP 連過的 Port */
void track_port(struct port_scan_entry *entry, __u16 port);

/* 功能10: 判斷是否觸發 Port Scan 警報 */
int  check_port_scan(struct port_scan_entry *entry, const struct pkt_info *info);

/* 功能14: 判斷是否觸發高流量攻擊警報 */
int  check_ddos(struct ddos_entry *entry, const struct pkt_info *info);

/* 供 proc_interface.c 使用的統計值 */
extern atomic_t g_portscan_count;
extern atomic_t g_ddos_count;

#endif /* DETECTOR_H */