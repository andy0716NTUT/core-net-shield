#ifndef LOGGER_H
#define LOGGER_H

#include <linux/types.h>

/* alert.log 路徑（在 userspace 的實際路徑） */
#define ALERT_LOG_PATH  "/var/log/net_guard/alert.log"

/* ------------------------------------------------------------------ */
/* 公開介面                                                              */
/* ------------------------------------------------------------------ */

/* 初始化 Logger (建立 log 檔、開啟 file handle) */
int  logger_init(void);

/* 清理 Logger */
void logger_exit(void);

/* 功能15: 建立警報紀錄（底層寫入函式） */
int  log_alert(const char *msg);

/* 功能16: 寫入 Port Scan 事件 */
void log_port_scan(__be32 src_ip, const __u16 *ports, int port_count);

/* 功能17: 寫入 DDoS / 高流量事件 */
void log_ddos(__be32 src_ip);

#endif /* LOGGER_H */