# Net Guard — Linux Kernel 網路流量監控與異常警示系統

## 專案結構

```
net_guard/
├── kernel/
│   ├── main.c              # 模組進入點，初始化/卸載所有子模組
│   ├── packet_hook.c       # Module 1: Netfilter Hook，攔截封包
│   ├── packet_hook.h
│   ├── detector.c          # Module 2: Port Scan & DDoS 偵測
│   ├── detector.h
│   ├── logger.c            # Module 3: 警報寫入 alert.log
│   ├── logger.h
│   ├── proc_interface.c    # Module 6: /proc/net_guard 管理介面
│   ├── proc_interface.h
│   └── Makefile
├── scripts/
│   ├── autoblock.sh        # Module 4: 讀 alert.log → iptables 封鎖
│   └── cleanup.sh          # Module 5: 逾時解除封鎖
├── logs/
│   ├── alert.log           # 警報日誌
│   └── block.log           # 封鎖紀錄
└── README.md
```

## 架構流程

```
封包進入
    │
    ▼
Linux Kernel Module (Netfilter Hook / NF_INET_PRE_ROUTING)
    │
    ├── Port Scan 偵測 ──────────────────┐
    │   10 秒內 > 20 個不同 Port         │
    │                                    ▼
    └── 高流量偵測 (DDoS) ──────► 異常事件紀錄 (alert.log)
        1 秒內 > 1000 packets             │
                                          ▼
                               Shell Script (autoblock.sh)
                               [crontab / 手動執行]
                                          │
                                          ▼
                               iptables -A INPUT -s <IP> -j DROP
                                          │
                                          ▼
                               封鎖紀錄 (block.log)
                                          │
                                          ▼
                               Shell Script (cleanup.sh)
                               [crontab */5 * * * *]
                                          │
                                          ▼
                               超過 30 分鐘 → iptables -D INPUT
                                          │
                                          ▼
                               block.log 標記 UNBLOCKED
```

## 編譯與安裝

### 1. 環境需求

```bash
# Debian / Ubuntu
sudo apt install build-essential linux-headers-$(uname -r)

# RHEL / CentOS / Fedora
sudo dnf install kernel-devel kernel-headers gcc make
```

### 2. 編譯 Kernel Module

```bash
cd net_guard/kernel
make
```

成功後會產生 `net_guard.ko`。

### 3. 建立 Log 目錄

```bash
sudo mkdir -p /var/log/net_guard
sudo touch /var/log/net_guard/alert.log
sudo touch /var/log/net_guard/block.log
```

### 4. 載入模組

```bash
sudo insmod net_guard.ko
# 或使用 Makefile 快捷指令
sudo make load
```

確認載入：

```bash
lsmod | grep net_guard
dmesg | tail -20
cat /proc/net_guard
```

### 5. 設定 Crontab

```bash
sudo crontab -e
```

加入以下兩行：

```cron
# 每分鐘執行 autoblock（讀 alert.log → iptables 封鎖）
* * * * * /path/to/net_guard/scripts/autoblock.sh >> /var/log/net_guard/autoblock_cron.log 2>&1

# 每 5 分鐘執行 cleanup（解除逾時封鎖）
*/5 * * * * /path/to/net_guard/scripts/cleanup.sh >> /var/log/net_guard/cleanup_cron.log 2>&1
```

### 6. 卸載模組

```bash
sudo rmmod net_guard
# 或
sudo make unload
```

---

## 功能對照表

| 功能編號 | 說明 | 實作位置 |
|---------|------|---------|
| 1 | Hook 註冊 (`nf_register_net_hook`) | `packet_hook.c: packet_hook_register()` |
| 2 | Hook 卸載 (`nf_unregister_net_hook`) | `packet_hook.c: packet_hook_unregister()` |
| 3 | 取得來源 IP | `packet_hook.c: parse_packet()` |
| 4 | 取得目的 IP | `packet_hook.c: parse_packet()` |
| 5 | 取得來源 Port | `packet_hook.c: parse_packet()` |
| 6 | 取得目的 Port | `packet_hook.c: parse_packet()` |
| 7 | 取得 Protocol (TCP/UDP/ICMP) | `packet_hook.c: parse_packet()` |
| 8 | 統計 IP 連過哪些 Port | `detector.c: track_port()` |
| 9 | 計算時間窗口 (10 秒) | `detector.c: check_port_scan()` |
| 10 | 判斷 Port Scan | `detector.c: check_port_scan()` |
| 11 | 封包計數器 | `detector.c: check_ddos()` |
| 12 | 時間統計 (1 秒) | `detector.c: check_ddos()` |
| 13 | 流量統計 (Bytes/sec) | `detector.c: check_ddos()` |
| 14 | 判斷高流量攻擊 | `detector.c: check_ddos()` |
| 15 | 建立警報紀錄 | `logger.c: log_alert()` |
| 16 | 寫入 Port Scan 事件 | `logger.c: log_port_scan()` |
| 17 | 寫入 DDoS 事件 | `logger.c: log_ddos()` |
| 18 | 記錄時間 (Timestamp) | `logger.c: get_timestamp()` |
| 19 | 記錄來源 IP | `logger.c: log_port_scan() / log_ddos()` |
| 20 | 記錄攻擊類型 | `logger.c: log_port_scan() / log_ddos()` |
| 21 | 讀取 alert.log | `autoblock.sh` |
| 22 | 擷取惡意 IP (grep/awk) | `autoblock.sh` |
| 23 | iptables 封鎖 | `autoblock.sh` |
| 24 | 避免重複封鎖 | `autoblock.sh` |
| 25 | 記錄 block.log | `autoblock.sh` |
| 26 | 讀取 block.log | `cleanup.sh` |
| 27 | 檢查封鎖時間 (30 分鐘) | `cleanup.sh` |
| 28 | 解除 iptables 規則 | `cleanup.sh` |
| 29 | 更新 block.log (UNBLOCKED) | `cleanup.sh` |
| 30 | 建立 /proc/net_guard | `proc_interface.c: proc_interface_init()` |
| 31 | 顯示系統狀態 | `proc_interface.c: net_guard_proc_show()` |
| 32 | 顯示偵測次數 | `proc_interface.c: net_guard_proc_show()` |
| 33 | 顯示目前封鎖 IP | `proc_interface.c: net_guard_proc_show()` |

---

## 偵測參數調整

偵測閾值定義在 `kernel/detector.h`：

```c
/* Port Scan */
#define PORTSCAN_TIME_WINDOW_SEC   10   // 時間窗口（秒）
#define PORTSCAN_PORT_THRESHOLD    20   // 觸發閾值（不同 Port 數）

/* DDoS */
#define DDOS_TIME_WINDOW_SEC        1   // 時間窗口（秒）
#define DDOS_PACKET_THRESHOLD    1000   // 封包數閾值（packets/sec）
```

封鎖持續時間定義在 `scripts/cleanup.sh`：

```bash
BLOCK_DURATION_SEC=$((30 * 60))   # 30 分鐘
```

---

## Log 格式範例

### alert.log

```
[2024-05-01 12:00:05] [ALERT] PORT SCAN src=192.168.1.10 port_count=22 ports=22,23,80,443,...
[2024-05-01 12:01:30] [ALERT] HIGH TRAFFIC src=10.0.0.5
```

### block.log

```
2024-05-01 12:00:10 BLOCKED 192.168.1.10
2024-05-01 12:01:35 BLOCKED 10.0.0.5
2024-05-01 12:00:10 BLOCKED 192.168.1.10 | 2024-05-01 12:30:10 UNBLOCKED
```

### /proc/net_guard

```
========================================
  Net Guard - Network Monitoring System
========================================
Status      : Module Running

Detection Statistics:
  Port Scan : 5
  DDoS      : 2

Currently Blocked IPs:
  192.168.1.10
  192.168.1.20
========================================
```