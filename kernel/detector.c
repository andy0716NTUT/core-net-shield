/*
 * detector.c - Module 2: Detection Module
 *
 * 功能：
 *   8.  統計 IP 連過哪些 Port
 *   9.  計算時間窗口 (10 秒)
 *   10. 判斷 Port Scan (10 秒內超過 20 個 Port → 觸發警報)
 *   11. 封包計數器
 *   12. 時間統計 (1 秒)
 *   13. 流量統計 (Bytes/sec)
 *   14. 判斷高流量攻擊 (1000 packets/sec → 觸發警報)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/inet.h>
#include <linux/atomic.h>

#include "detector.h"
#include "logger.h"

/* ------------------------------------------------------------------ */
/* 全域偵測計數 (供 proc_interface 讀取)                                 */
/* ------------------------------------------------------------------ */
atomic_t g_portscan_count = ATOMIC_INIT(0);
atomic_t g_ddos_count     = ATOMIC_INIT(0);
EXPORT_SYMBOL(g_portscan_count);
EXPORT_SYMBOL(g_ddos_count);

/* ------------------------------------------------------------------ */
/* 追蹤表與鎖                                                            */
/* ------------------------------------------------------------------ */
static struct port_scan_entry ps_table[MAX_TRACK_IPS];
static struct ddos_entry      ddos_table[MAX_TRACK_IPS];

static DEFINE_SPINLOCK(ps_lock);
static DEFINE_SPINLOCK(ddos_lock);

/* ------------------------------------------------------------------ */
/* 初始化                                                                */
/* ------------------------------------------------------------------ */
int detector_init(void)
{
    memset(ps_table,   0, sizeof(ps_table));
    memset(ddos_table, 0, sizeof(ddos_table));
    pr_info("net_guard: Detection Module 初始化完成\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* 清理                                                                  */
/* ------------------------------------------------------------------ */
void detector_exit(void)
{
    pr_info("net_guard: Detection Module 已卸載\n");
}

/* ------------------------------------------------------------------ */
/* 功能8: 尋找或建立 Port Scan 追蹤表項目                               */
/* ------------------------------------------------------------------ */
static struct port_scan_entry *find_or_create_ps_entry(__be32 src_ip)
{
    int i, empty = -1;

    for (i = 0; i < MAX_TRACK_IPS; i++) {
        if (ps_table[i].used && ps_table[i].src_ip == src_ip)
            return &ps_table[i];
        if (!ps_table[i].used && empty < 0)
            empty = i;
    }

    /* 建立新項目 */
    if (empty >= 0) {
        memset(&ps_table[empty], 0, sizeof(struct port_scan_entry));
        ps_table[empty].src_ip       = src_ip;
        ps_table[empty].window_start = ktime_get();
        ps_table[empty].used         = 1;
        return &ps_table[empty];
    }

    return NULL; /* 表滿，無法追蹤 */
}

/* ------------------------------------------------------------------ */
/* 功能8: 統計 IP 連過哪些 Port（去重複）                               */
/* ------------------------------------------------------------------ */
void track_port(struct port_scan_entry *entry, __u16 port)
{
    int i;

    /* 若已在清單中，跳過 */
    for (i = 0; i < entry->port_count; i++) {
        if (entry->ports[i] == port)
            return;
    }

    /* 加入新 Port */
    if (entry->port_count < MAX_PORTS_PER_IP) {
        entry->ports[entry->port_count++] = port;
    }
}

/* ------------------------------------------------------------------ */
/* 功能9 & 10: 判斷是否觸發 Port Scan 警報                              */
/* ------------------------------------------------------------------ */
int check_port_scan(struct port_scan_entry *entry,
                    const struct pkt_info  *info)
{
    ktime_t  now     = ktime_get();
    s64      elapsed = ktime_to_ms(ktime_sub(now, entry->window_start));

    /* 功能9: 檢查是否在時間窗口內 */
    if (elapsed > (PORTSCAN_TIME_WINDOW_SEC * 1000)) {
        /* 窗口已過，重置計數 */
        entry->window_start = now;
        entry->port_count   = 0;
        memset(entry->ports, 0, sizeof(entry->ports));

        /* 把當前 Port 加入新窗口 */
        track_port(entry, info->dst_port);
        return 0;
    }

    /* 在窗口內：記錄此 Port */
    track_port(entry, info->dst_port);

    /* 功能10: 超過閾值 → 觸發警報 */
    if (entry->port_count >= PORTSCAN_PORT_THRESHOLD) {
        return 1; /* 偵測到 Port Scan */
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* 功能11-13: 尋找或建立 DDoS 追蹤表項目                               */
/* ------------------------------------------------------------------ */
static struct ddos_entry *find_or_create_ddos_entry(__be32 src_ip)
{
    int i, empty = -1;

    for (i = 0; i < MAX_TRACK_IPS; i++) {
        if (ddos_table[i].used && ddos_table[i].src_ip == src_ip)
            return &ddos_table[i];
        if (!ddos_table[i].used && empty < 0)
            empty = i;
    }

    if (empty >= 0) {
        memset(&ddos_table[empty], 0, sizeof(struct ddos_entry));
        ddos_table[empty].src_ip       = src_ip;
        ddos_table[empty].window_start = ktime_get();
        ddos_table[empty].used         = 1;
        return &ddos_table[empty];
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/* 功能12 & 14: 判斷是否觸發高流量攻擊警報                              */
/* ------------------------------------------------------------------ */
int check_ddos(struct ddos_entry     *entry,
               const struct pkt_info *info)
{
    ktime_t now     = ktime_get();
    s64     elapsed = ktime_to_ms(ktime_sub(now, entry->window_start));

    /* 功能11: 封包計數器 & 功能13: 流量統計 */
    entry->pkt_count++;
    entry->byte_count += info->pkt_len;

    /* 功能12: 時間統計 - 1 秒窗口 */
    if (elapsed > (DDOS_TIME_WINDOW_SEC * 1000)) {
        u64 pkts_per_sec  = entry->pkt_count;
        u64 bytes_per_sec = entry->byte_count;

        /* 重置計數 */
        entry->window_start = now;
        entry->pkt_count    = 0;
        entry->byte_count   = 0;

        /* 功能14: 判斷高流量攻擊 */
        if (pkts_per_sec >= DDOS_PACKET_THRESHOLD) {
            pr_debug("net_guard: DDoS 流量統計 - %llu pkts/sec, %llu bytes/sec\n",
                     pkts_per_sec, bytes_per_sec);
            return 1; /* 偵測到高流量攻擊 */
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* 主要入口：被 packet_hook.c 的 Hook 回呼呼叫                          */
/* ------------------------------------------------------------------ */
void detect_packet(const struct pkt_info *info)
{
    unsigned long flags;

    /* ---------- Port Scan 偵測 (TCP/UDP) ---------- */
    if (info->protocol == IPPROTO_TCP ||
        info->protocol == IPPROTO_UDP) {

        spin_lock_irqsave(&ps_lock, flags);
        {
            struct port_scan_entry *ps_entry =
                find_or_create_ps_entry(info->src_ip);

            if (ps_entry) {
                if (check_port_scan(ps_entry, info)) {
                    /* 功能10: 觸發 Port Scan 警報 */
                    atomic_inc(&g_portscan_count);
                    spin_unlock_irqrestore(&ps_lock, flags);

                    /* 記錄到 alert.log (功能16) */
                    log_port_scan(info->src_ip,
                                  ps_entry->ports,
                                  ps_entry->port_count);

                    /* 重置此 IP 的計數，避免連續重複警報 */
                    spin_lock_irqsave(&ps_lock, flags);
                    ps_entry->port_count   = 0;
                    ps_entry->window_start = ktime_get();
                    memset(ps_entry->ports, 0, sizeof(ps_entry->ports));
                }
            }
        }
        spin_unlock_irqrestore(&ps_lock, flags);
    }

    /* ---------- DDoS / 高流量偵測 ---------- */
    spin_lock_irqsave(&ddos_lock, flags);
    {
        struct ddos_entry *ddos_entry =
            find_or_create_ddos_entry(info->src_ip);

        if (ddos_entry) {
            if (check_ddos(ddos_entry, info)) {
                /* 功能14: 觸發高流量警報 */
                atomic_inc(&g_ddos_count);
                spin_unlock_irqrestore(&ddos_lock, flags);

                /* 記錄到 alert.log (功能17) */
                log_ddos(info->src_ip);

                spin_lock_irqsave(&ddos_lock, flags);
            }
        }
    }
    spin_unlock_irqrestore(&ddos_lock, flags);
}