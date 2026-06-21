/*
 * logger.c - Module 3: Logging Module
 *
 * 功能：
 *   15. 建立警報紀錄 (alert.log)
 *   16. 寫入 Port Scan 事件  [ALERT] PORT SCAN
 *   17. 寫入 DDoS 事件       [ALERT] HIGH TRAFFIC
 *   18. 記錄時間 (Timestamp)
 *   19. 記錄來源 IP
 *   20. 記錄攻擊類型 (SCAN / DDoS)
 *
 * 注意： 感覺要改用 netlink socket 通知 userspace daemon 寫檔。
 *       不過為了簡化實作，這裡直接在 kernel module 中寫檔。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/timekeeping.h>
#include <linux/rtc.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "logger.h"

/* 每則日誌訊息最大長度 */
#define LOG_BUF_SIZE  512

/* ------------------------------------------------------------------ */
/* 功能18: 取得目前時間字串，格式: [YYYY-MM-DD HH:MM:SS]               */
/* ------------------------------------------------------------------ */
static void get_timestamp(char *buf, size_t len)
{
    struct timespec64 ts;
    struct tm         tm_val;

    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &tm_val);

    snprintf(buf, len, "[%04ld-%02d-%02d %02d:%02d:%02d]",
             tm_val.tm_year + 1900,
             tm_val.tm_mon  + 1,
             tm_val.tm_mday,
             tm_val.tm_hour,
             tm_val.tm_min,
             tm_val.tm_sec);
}

/* ------------------------------------------------------------------ */
/* 功能15: 底層寫入函式 - 將訊息附加到 alert.log                        */
/* ------------------------------------------------------------------ */
int log_alert(const char *msg)
{
    struct file *fp;
    loff_t       pos;
    ssize_t      ret;

    fp = filp_open(ALERT_LOG_PATH,
                   O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(fp)) {
        pr_err("net_guard: 無法開啟 %s (err=%ld)\n",
               ALERT_LOG_PATH, PTR_ERR(fp));
        return PTR_ERR(fp);
    }

    pos = fp->f_pos;
    ret = kernel_write(fp, msg, strlen(msg), &pos);
    if (ret < 0)
        pr_err("net_guard: 寫入 alert.log 失敗 (err=%zd)\n", ret);

    filp_close(fp, NULL);
    return (ret < 0) ? ret : 0;
}

/* ------------------------------------------------------------------ */
/* 功能16: 寫入 Port Scan 事件                                           */
/* ------------------------------------------------------------------ */
void log_port_scan(__be32 src_ip, const __u16 *ports, int port_count)
{
    char ts[32];
    char ip_str[16];
    char ports_str[256];
    char log_line[LOG_BUF_SIZE];
    int  i, offset = 0;

    /* 功能18: 時間戳 */
    get_timestamp(ts, sizeof(ts));

    /* 功能19: 來源 IP */
    snprintf(ip_str, sizeof(ip_str), "%pI4", &src_ip);

    /* 掃描的 Port 清單 */
    for (i = 0; i < port_count && offset < (int)sizeof(ports_str) - 8; i++) {
        offset += snprintf(ports_str + offset,
                           sizeof(ports_str) - offset,
                           "%u%s",
                           ports[i],
                           (i < port_count - 1) ? "," : "");
    }

    /*
     * 功能16 & 20: 格式化日誌行
     * 範例: [2024-05-01 12:00:00] [ALERT] PORT SCAN src=192.168.1.10 ports=22,80,443,...
     */
    snprintf(log_line, sizeof(log_line),
             "%s [ALERT] PORT SCAN src=%s port_count=%d ports=%s\n",
             ts, ip_str, port_count, ports_str);

    /* 寫入 alert.log */
    log_alert(log_line);

    /* 同步輸出到 kernel log */
    pr_warn("net_guard: %s", log_line);
}

/* ------------------------------------------------------------------ */
/* 功能17: 寫入 DDoS / 高流量事件                                        */
/* ------------------------------------------------------------------ */
void log_ddos(__be32 src_ip)
{
    char ts[32];
    char ip_str[16];
    char log_line[LOG_BUF_SIZE];

    /* 功能18: 時間戳 */
    get_timestamp(ts, sizeof(ts));

    /* 功能19: 來源 IP */
    snprintf(ip_str, sizeof(ip_str), "%pI4", &src_ip);

    /*
     * 功能17 & 20: 格式化日誌行
     * 範例: [2024-05-01 12:00:00] [ALERT] HIGH TRAFFIC src=192.168.1.10
     */
    snprintf(log_line, sizeof(log_line),
             "%s [ALERT] HIGH TRAFFIC src=%s\n",
             ts, ip_str);

    /* 寫入 alert.log */
    log_alert(log_line);

    /* 同步輸出到 kernel log */
    pr_warn("net_guard: %s", log_line);
}

/* ------------------------------------------------------------------ */
/* 初始化 Logger                                                         */
/* ------------------------------------------------------------------ */
int logger_init(void)
{
    struct file *fp;

    /* 確保 log 目錄存在（實際應由 systemd / install script 建立） */
    fp = filp_open(ALERT_LOG_PATH,
                   O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(fp)) {
        pr_err("net_guard: logger_init - 無法建立 %s\n", ALERT_LOG_PATH);
        return PTR_ERR(fp);
    }
    filp_close(fp, NULL);

    pr_info("net_guard: Logger 初始化完成，日誌路徑: %s\n", ALERT_LOG_PATH);
    return 0;
}

/* ------------------------------------------------------------------ */
/* 清理 Logger                                                           */
/* ------------------------------------------------------------------ */
void logger_exit(void)
{
    pr_info("net_guard: Logger 已卸載\n");
}