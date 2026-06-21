# Makefile - Net Guard Kernel Module
#
# 使用方式：
#   make          → 編譯模組
#   make clean    → 清理編譯產物
#   make load     → 載入模組 (需要 root)
#   make unload   → 卸載模組 (需要 root)
#   make status   → 查看 /proc/net_guard

# 模組名稱
MODULE_NAME := net_guard

# 組成 kernel module 的目標檔
obj-m += $(MODULE_NAME).o

$(MODULE_NAME)-objs := main.o          \
                       packet_hook.o   \
                       detector.o      \
                       logger.o        \
                       proc_interface.o

# Kernel 來源路徑（預設使用目前執行中的 kernel）
KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

# 目前目錄
PWD := $(shell pwd)

# ------------------------------------------------------------------ #
# 預設目標：編譯 kernel module                                         #
# ------------------------------------------------------------------ #
all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

# ------------------------------------------------------------------ #
# 清理                                                                 #
# ------------------------------------------------------------------ #
clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	rm -f modules.order Module.symvers

# ------------------------------------------------------------------ #
# 載入模組（需要 root 權限）                                            #
# ------------------------------------------------------------------ #
load:
	@echo "[*] 建立 log 目錄..."
	mkdir -p /var/log/net_guard
	touch /var/log/net_guard/alert.log
	touch /var/log/net_guard/block.log
	@echo "[*] 載入模組..."
	insmod $(MODULE_NAME).ko
	@echo "[+] 模組已載入"
	@echo "[*] 狀態："
	cat /proc/net_guard

# ------------------------------------------------------------------ #
# 卸載模組                                                              #
# ------------------------------------------------------------------ #
unload:
	@echo "[*] 卸載模組..."
	rmmod $(MODULE_NAME)
	@echo "[+] 模組已卸載"

# ------------------------------------------------------------------ #
# 查看狀態                                                              #
# ------------------------------------------------------------------ #
status:
	@cat /proc/net_guard

.PHONY: all clean load unload status