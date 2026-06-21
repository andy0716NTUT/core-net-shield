/*
 * main.c - Net Guard Kernel Module Entry Point
 *
 * 負責依序初始化與清理所有子模組：
 *   1. Logger          (logger_init / logger_exit)
 *   2. Detector        (detector_init / detector_exit)
 *   3. Packet Hook     (packet_hook_register / packet_hook_unregister)
 *   4. Proc Interface  (proc_interface_init / proc_interface_exit)
 *
 * 載入:   insmod net_guard.ko
 * 卸載:   rmmod  net_guard
 * 狀態:   cat /proc/net_guard
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include "packet_hook.h"
#include "detector.h"
#include "logger.h"
#include "proc_interface.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Net Guard Team");
MODULE_DESCRIPTION("Linux Kernel Network Traffic Monitor & Anomaly Alert System");
MODULE_VERSION("1.0");

/* ------------------------------------------------------------------ */
/* 模組載入                                                              */
/* ------------------------------------------------------------------ */
static int __init net_guard_init(void)
{
    int ret;

    pr_info("net_guard: ===== 模組載入中 =====\n");

    /* Step 1: 初始化 Logger */
    ret = logger_init();
    if (ret < 0) {
        pr_err("net_guard: logger_init 失敗 (%d)\n", ret);
        return ret;
    }

    /* Step 2: 初始化 Detection Module */
    ret = detector_init();
    if (ret < 0) {
        pr_err("net_guard: detector_init 失敗 (%d)\n", ret);
        goto err_logger;
    }

    /* Step 3: 註冊 Netfilter Hook */
    ret = packet_hook_register();
    if (ret < 0) {
        pr_err("net_guard: packet_hook_register 失敗 (%d)\n", ret);
        goto err_detector;
    }

    /* Step 4: 建立 /proc/net_guard */
    ret = proc_interface_init();
    if (ret < 0) {
        pr_err("net_guard: proc_interface_init 失敗 (%d)\n", ret);
        goto err_hook;
    }

    pr_info("net_guard: ===== 模組載入完成 =====\n");
    pr_info("net_guard: 查看狀態: cat /proc/net_guard\n");
    return 0;

    /* 逆序清理錯誤路徑 */
err_hook:
    packet_hook_unregister();
err_detector:
    detector_exit();
err_logger:
    logger_exit();
    return ret;
}

/* ------------------------------------------------------------------ */
/* 模組卸載                                                              */
/* ------------------------------------------------------------------ */
static void __exit net_guard_exit(void)
{
    pr_info("net_guard: ===== 模組卸載中 =====\n");

    /* 逆序清理，確保安全 */
    proc_interface_exit();
    packet_hook_unregister();
    detector_exit();
    logger_exit();

    pr_info("net_guard: ===== 模組已卸載 =====\n");
}

module_init(net_guard_init);
module_exit(net_guard_exit);