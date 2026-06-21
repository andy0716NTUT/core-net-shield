/*
 * proc_interface.c - Module 6: Management Module
 *
 * 功能：
 *   30. 建立 /proc/net_guard
 *   31. 顯示系統狀態      (Module Running)
 *   32. 顯示偵測次數      (Port Scan: N  DDoS: N)
 *   33. 顯示目前封鎖 IP   (來自 block.log / iptables 紀錄)
 *
 * 使用方式：
 *   cat /proc/net_guard
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/inet.h>
#include <linux/string.h>

#include "proc_interface.h"
#include "detector.h"

/* ------------------------------------------------------------------ */
/* 封鎖 IP 清單                                                          */
/* ------------------------------------------------------------------ */
static __be32          blocked_ips[MAX_BLOCKED_IPS];
static int             blocked_ip_count = 0;
static DEFINE_SPINLOCK(blocked_ip_lock);

/* proc 節點指標 */
static struct proc_dir_entry *proc_entry = NULL;

/* ------------------------------------------------------------------ */
/* 新增封鎖 IP                                                           */
/* ------------------------------------------------------------------ */
void proc_add_blocked_ip(__be32 ip)
{
    int i;
    unsigned long flags;

    spin_lock_irqsave(&blocked_ip_lock, flags);

    /* 避免重複 */
    for (i = 0; i < blocked_ip_count; i++) {
        if (blocked_ips[i] == ip)
            goto out;
    }

    if (blocked_ip_count < MAX_BLOCKED_IPS) {
        blocked_ips[blocked_ip_count++] = ip;
    }

out:
    spin_unlock_irqrestore(&blocked_ip_lock, flags);
}
EXPORT_SYMBOL(proc_add_blocked_ip);

/* ------------------------------------------------------------------ */
/* 移除封鎖 IP                                                           */
/* ------------------------------------------------------------------ */
void proc_remove_blocked_ip(__be32 ip)
{
    int i;
    unsigned long flags;

    spin_lock_irqsave(&blocked_ip_lock, flags);

    for (i = 0; i < blocked_ip_count; i++) {
        if (blocked_ips[i] == ip) {
            /* 以最後一個項目填補空缺 */
            blocked_ips[i] = blocked_ips[--blocked_ip_count];
            break;
        }
    }

    spin_unlock_irqrestore(&blocked_ip_lock, flags);
}
EXPORT_SYMBOL(proc_remove_blocked_ip);

/* ------------------------------------------------------------------ */
/* 功能30-33: /proc/net_guard 讀取回呼                                  */
/* ------------------------------------------------------------------ */
static int net_guard_proc_show(struct seq_file *m, void *v)
{
    int           i;
    unsigned long flags;

    /* 功能31: 顯示系統狀態 */
    seq_puts(m, "========================================\n");
    seq_puts(m, "  Net Guard - Network Monitoring System \n");
    seq_puts(m, "========================================\n");
    seq_puts(m, "Status      : Module Running\n\n");

    /* 功能32: 顯示偵測次數 */
    seq_printf(m, "Detection Statistics:\n");
    seq_printf(m, "  Port Scan : %d\n", atomic_read(&g_portscan_count));
    seq_printf(m, "  DDoS      : %d\n\n", atomic_read(&g_ddos_count));

    /* 功能33: 顯示目前封鎖 IP */
    seq_puts(m, "Currently Blocked IPs:\n");

    spin_lock_irqsave(&blocked_ip_lock, flags);
    if (blocked_ip_count == 0) {
        seq_puts(m, "  (none)\n");
    } else {
        for (i = 0; i < blocked_ip_count; i++) {
            seq_printf(m, "  %pI4\n", &blocked_ips[i]);
        }
    }
    spin_unlock_irqrestore(&blocked_ip_lock, flags);

    seq_puts(m, "========================================\n");
    return 0;
}

/* seq_file open */
static int net_guard_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, net_guard_proc_show, NULL);
}

/* proc 檔案操作 */
static const struct proc_ops net_guard_proc_ops = {
    .proc_open    = net_guard_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ------------------------------------------------------------------ */
/* 功能30: 建立 /proc/net_guard                                         */
/* ------------------------------------------------------------------ */
int proc_interface_init(void)
{
    proc_entry = proc_create(PROC_NAME, 0444, NULL, &net_guard_proc_ops);
    if (!proc_entry) {
        pr_err("net_guard: 無法建立 /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }

    pr_info("net_guard: /proc/%s 已建立\n", PROC_NAME);
    return 0;
}

/* ------------------------------------------------------------------ */
/* 移除 /proc/net_guard                                                 */
/* ------------------------------------------------------------------ */
void proc_interface_exit(void)
{
    if (proc_entry) {
        proc_remove(proc_entry);
        proc_entry = NULL;
    }
    pr_info("net_guard: /proc/%s 已移除\n", PROC_NAME);
}