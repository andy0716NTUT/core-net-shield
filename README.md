# Core Net Shield - Linux Kernel 網路流量監控與異常警示系統

Core Net Shield 是一個以 Linux Kernel Module 實作的網路安全監控專案。系統會在核心層透過 Netfilter Hook 攔截 IPv4 封包，偵測 Port Scan 與高流量攻擊，將異常事件寫入 `alert.log`，再由使用者空間腳本自動封鎖來源 IP、統計違規次數，並支援超過門檻後永久封鎖。

GitHub repo 建議名稱：

```text
core-net-shield
```

## 專案結構

```text
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
│   ├── autoblock.sh        # 讀 alert.log，統計違規，封鎖/永久封鎖 IP
│   ├── cleanup.sh          # 解除逾時封鎖；永久封鎖不自動解除
│   └── unban.sh            # 手動解除單一 IP 或全部封鎖
├── tools/
│   └── test_net_guard_windows.py  # Windows 端 SSH 自動測試腳本
├── logs/
│   ├── alert.log           # 範例/占位警報日誌
│   └── block.log           # 範例/占位封鎖紀錄
└── README.md
```

## 架構流程

```text
封包進入
    │
    ▼
Linux Kernel Module (Netfilter Hook / NF_INET_PRE_ROUTING)
    │
    ├── Port Scan 偵測：10 秒內 >= 20 個不同 Port
    │
    └── 高流量偵測：1 秒內 >= 1000 packets
                 │
                 ▼
          alert.log 記錄異常事件
                 │
                 ▼
          autoblock.sh 每分鐘讀取新增 alert
                 │
                 ├── 更新 violations.db 違規次數
                 ├── iptables -A INPUT -s <IP> -j DROP
                 ├── 寫入 block.log
                 └── 違規次數 >= 5 時標記 PERMABANNED
                         │
                         ▼
          cleanup.sh 每 5 分鐘解除一般逾時封鎖
                 │
                 └── PERMABANNED 不自動解除
                         │
                         ▼
          unban.sh 手動解除單一 IP 或全部封鎖
```

## 環境需求

Ubuntu/Debian：

```bash
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r)
```

RHEL/CentOS/Fedora：

```bash
sudo dnf install kernel-devel kernel-headers gcc make
```

系統需要 root 權限才能載入 kernel module、修改 `/proc/net_guard`、操作 `iptables` 與安裝 root crontab。

## 編譯與載入

```bash
cd ~/core-net-shield/kernel
make
```

成功後會產生：

```text
net_guard.ko
```

建立 log 目錄：

```bash
sudo mkdir -p /var/log/net_guard
sudo touch /var/log/net_guard/alert.log
sudo touch /var/log/net_guard/block.log
sudo touch /var/log/net_guard/violations.db
sudo touch /var/log/net_guard/alert.offset
```

載入模組：

```bash
sudo insmod net_guard.ko
```

或使用 Makefile：

```bash
sudo make load
```

確認狀態：

```bash
lsmod | grep net_guard
dmesg | tail -20
cat /proc/net_guard
```

卸載模組：

```bash
sudo rmmod net_guard
```

或：

```bash
sudo make unload
```

## Crontab 自動化

用 root crontab 安裝兩條排程：

```bash
sudo crontab -e
```

加入：

```cron
* * * * * /home/andy/core-net-shield/scripts/autoblock.sh >> /var/log/net_guard/autoblock_cron.log 2>&1
*/5 * * * * /home/andy/core-net-shield/scripts/cleanup.sh >> /var/log/net_guard/cleanup_cron.log 2>&1
```

確認：

```bash
sudo crontab -l
```

## 功能對照表

| 編號 | 說明 | 實作位置 |
|---:|---|---|
| 1 | Hook 註冊 (`nf_register_net_hook`) | `packet_hook.c: packet_hook_register()` |
| 2 | Hook 卸載 (`nf_unregister_net_hook`) | `packet_hook.c: packet_hook_unregister()` |
| 3 | 取得來源 IP | `packet_hook.c: parse_packet()` |
| 4 | 取得目的 IP | `packet_hook.c: parse_packet()` |
| 5 | 取得來源 Port | `packet_hook.c: parse_packet()` |
| 6 | 取得目的 Port | `packet_hook.c: parse_packet()` |
| 7 | 取得 Protocol (TCP/UDP/ICMP) | `packet_hook.c: parse_packet()` |
| 8 | 統計 IP 連過哪些 Port | `detector.c: track_port()` |
| 9 | 計算 Port Scan 時間窗口 | `detector.c: check_port_scan()` |
| 10 | 判斷 Port Scan | `detector.c: check_port_scan()` |
| 11 | 封包計數器 | `detector.c: check_ddos()` |
| 12 | 計算 DDoS 時間窗口 | `detector.c: check_ddos()` |
| 13 | 流量統計 Bytes/sec | `detector.c: check_ddos()` |
| 14 | 判斷高流量攻擊 | `detector.c: check_ddos()` |
| 15 | 建立警報紀錄 | `logger.c: log_alert()` |
| 16 | 寫入 Port Scan 事件 | `logger.c: log_port_scan()` |
| 17 | 寫入 DDoS 事件 | `logger.c: log_ddos()` |
| 18 | 記錄時間 Timestamp | `logger.c: get_timestamp()` |
| 19 | 記錄來源 IP | `logger.c: log_port_scan()` / `log_ddos()` |
| 20 | 記錄攻擊類型 | `logger.c: log_port_scan()` / `log_ddos()` |
| 21 | 讀取 `alert.log` 新增警報 | `scripts/autoblock.sh` |
| 22 | 使用 `alert.offset` 避免重複計算同一筆 alert | `scripts/autoblock.sh` |
| 23 | 更新每個 IP 的違規次數 | `scripts/autoblock.sh` |
| 24 | 超過門檻後永久封鎖 | `scripts/autoblock.sh` |
| 25 | iptables 封鎖 | `scripts/autoblock.sh` |
| 26 | 避免重複封鎖 | `scripts/autoblock.sh` |
| 27 | 記錄 `block.log` | `scripts/autoblock.sh` |
| 28 | 讀取 `block.log` | `scripts/cleanup.sh` |
| 29 | 檢查一般封鎖時間 | `scripts/cleanup.sh` |
| 30 | 解除一般 iptables 規則 | `scripts/cleanup.sh` |
| 31 | 永久封鎖不自動解除 | `scripts/cleanup.sh` |
| 32 | 手動解除單一 IP | `scripts/unban.sh` |
| 33 | 手動解除所有追蹤 IP | `scripts/unban.sh` |
| 34 | 建立 `/proc/net_guard` | `proc_interface.c: proc_interface_init()` |
| 35 | 顯示系統狀態 | `proc_interface.c: net_guard_proc_show()` |
| 36 | 顯示偵測次數 | `proc_interface.c: net_guard_proc_show()` |
| 37 | 顯示目前封鎖 IP | `proc_interface.c: net_guard_proc_show()` |
| 38 | 讓 userspace 腳本用 `+IP` / `-IP` 同步封鎖清單 | `proc_interface.c: net_guard_proc_write()` |

## 偵測與封鎖參數

Kernel 偵測閾值定義在 `kernel/detector.h`：

```c
/* Port Scan */
#define PORTSCAN_TIME_WINDOW_SEC   10
#define PORTSCAN_PORT_THRESHOLD    20

/* DDoS */
#define DDOS_TIME_WINDOW_SEC        1
#define DDOS_PACKET_THRESHOLD    1000
```

腳本參數可用環境變數調整：

```bash
# 一般封鎖時間，預設 1800 秒，也就是 30 分鐘
BLOCK_DURATION_SEC=1800

# 永久封鎖門檻，預設 5 次
PERMABAN_THRESHOLD=5
```

例：

```bash
sudo PERMABAN_THRESHOLD=6 /home/andy/core-net-shield/scripts/autoblock.sh
sudo BLOCK_DURATION_SEC=60 /home/andy/core-net-shield/scripts/cleanup.sh
```

## Log 與資料檔

### alert.log

Kernel module 偵測到異常後會寫入：

```text
[2024-05-01 12:00:05] [ALERT] PORT SCAN src=192.168.1.10 port_count=22 ports=22,23,80,443
[2024-05-01 12:01:30] [ALERT] HIGH TRAFFIC src=10.0.0.5
```

### alert.offset

`autoblock.sh` 用來記錄上次讀到 `alert.log` 的 byte offset，避免 crontab 每分鐘重複計算同一筆警報。

### violations.db

每個 IP 的違規次數紀錄：

```text
192.168.1.10 1 ACTIVE 1714550405
10.0.0.5 5 PERMABANNED 1714550490
```

欄位：

```text
IP 違規次數 狀態 最後違規時間epoch
```

狀態：

```text
ACTIVE       一般追蹤中
PERMABANNED 永久封鎖，不會被 cleanup.sh 自動解除
```

### block.log

封鎖、永久封鎖、解除封鎖紀錄：

```text
2024-05-01 12:00:10 BLOCKED 192.168.1.10
2024-05-01 12:30:10 BLOCKED 192.168.1.10 | 2024-05-01 13:00:10 UNBLOCKED
2024-05-01 12:10:00 PERMABANNED 10.0.0.5 violations=5 previous=4
2024-05-01 13:20:00 MANUAL_UNBAN 10.0.0.5
```

### /proc/net_guard

```text
========================================
  Net Guard - Network Monitoring System
========================================
Status      : Module Running

Detection Statistics:
  Port Scan : 5
  DDoS      : 2

Currently Blocked IPs:
  192.168.1.10
========================================
```

## 手動測試

以下命令請在 Ubuntu 上執行。

### 1. 確認模組狀態

```bash
lsmod | grep net_guard
cat /proc/net_guard
```

### 2. 模擬一次違規

```bash
sudo sh -c 'echo "[2026-06-21 00:00:00] [ALERT] PORT SCAN src=203.0.113.10 port_count=22 ports=1,2,3" >> /var/log/net_guard/alert.log'
sudo /home/andy/core-net-shield/scripts/autoblock.sh
```

確認封鎖：

```bash
sudo iptables -C INPUT -s 203.0.113.10 -j DROP && echo blocked
cat /proc/net_guard
sudo cat /var/log/net_guard/violations.db
```

### 3. 測試一般封鎖可解除

```bash
sudo BLOCK_DURATION_SEC=0 /home/andy/core-net-shield/scripts/cleanup.sh
sudo iptables -C INPUT -s 203.0.113.10 -j DROP || echo unblocked
```

### 4. 模擬 5 次違規進入永久封鎖

```bash
for i in 1 2 3 4 5; do
  sudo sh -c "echo \"[2026-06-21 00:00:0$i] [ALERT] PORT SCAN src=203.0.113.20 port_count=22 ports=1,2,3\" >> /var/log/net_guard/alert.log"
done

sudo /home/andy/core-net-shield/scripts/autoblock.sh
sudo cat /var/log/net_guard/violations.db
```

預期看到：

```text
203.0.113.20 5 PERMABANNED ...
```

### 5. 測試永久封鎖不會被 cleanup 解除

```bash
sudo BLOCK_DURATION_SEC=0 /home/andy/core-net-shield/scripts/cleanup.sh
sudo iptables -C INPUT -s 203.0.113.20 -j DROP && echo still-banned
```

### 6. 手動解除封鎖

解除單一 IP：

```bash
sudo /home/andy/core-net-shield/scripts/unban.sh 203.0.113.20
```

解除所有追蹤與封鎖：

```bash
sudo /home/andy/core-net-shield/scripts/unban.sh --all
```

## Windows 一鍵測試

Windows 端可用 `tools/test_net_guard_windows.py` 透過 SSH 測試遠端 Ubuntu。

需求：

- Windows 已安裝 Python 3
- Windows OpenSSH 可用，也就是 `ssh` 與 `scp` 指令可執行
- Ubuntu 遠端已部署專案到 `/home/andy/core-net-shield`
- Ubuntu 遠端已載入 `net_guard.ko`

執行：

```powershell
cd "C:\Users\andyl\Downloads\Linux Kernel Module\Linux Kernel Module"
python .\tools\test_net_guard_windows.py --host 192.168.64.129 --user andy --sudo-password andy
```

如果沒有設定 SSH key，執行過程中 Windows 會要求輸入 SSH 密碼。輸入：

```text
andy
```

測試內容：

```text
1. 確認 /proc/net_guard 存在
2. 模擬一次違規並確認 iptables 封鎖
3. 測試 cleanup 可解除一般封鎖
4. 模擬 5 次違規並確認 PERMABANNED
5. 確認 cleanup 不會解除永久封鎖
6. 執行 unban.sh 清除封鎖與 violations.db
7. 確認測試 IP 的 iptables 規則已清除
```

成功時會看到：

```text
TEST1 temporary block cleanup: PASS
TEST2 permaban survives cleanup: PASS
TEST3 manual unban clears rule and db: PASS
ALL TESTS PASSED
```

## 目前遠端部署紀錄

本專案已在以下環境測試通過：

```text
Host: 192.168.64.129
User: andy
Kernel: 5.4.0-150-generic
Deploy path: /home/andy/core-net-shield
Module: /home/andy/core-net-shield/kernel/net_guard.ko
```

已驗證：

```text
make 編譯成功
insmod 載入成功
/proc/net_guard 顯示正常
autoblock.sh 封鎖成功
cleanup.sh 解除一般封鎖成功
PERMABANNED 不被 cleanup 解除
unban.sh 可清除單一 IP
root crontab 已加入 autoblock/cleanup 排程
```
