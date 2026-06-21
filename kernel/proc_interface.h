#ifndef PROC_INTERFACE_H
#define PROC_INTERFACE_H

/* /proc 節點名稱 */
#define PROC_NAME "net_guard"

/* ------------------------------------------------------------------ */
/* 公開介面                                                              */
/* ------------------------------------------------------------------ */

/* 功能30: 建立 /proc/net_guard */
int  proc_interface_init(void);

/* 移除 /proc/net_guard */
void proc_interface_exit(void);

/* ------------------------------------------------------------------ */
/* 封鎖 IP 清單 (供 autoblock.sh → proc 讀取) */
/* ------------------------------------------------------------------ */
#define MAX_BLOCKED_IPS  64

/* 新增封鎖 IP (由 logger 或外部呼叫) */
void proc_add_blocked_ip(__be32 ip);

/* 清除封鎖 IP */
void proc_remove_blocked_ip(__be32 ip);

#endif /* PROC_INTERFACE_H */