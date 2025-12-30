/*
 * Watchdog 使用示例
 * 
 * 这个文件演示如何在主程序中集成 Watchdog
 */

#include <stdio.h>
#include <windows.h>
#include "Watchdog.h"

// 主程序入口示例
int main_with_watchdog_example(int argc, char **argv) {
    printf("=== MTC Main Program with Watchdog ===\n\n");
    
    // 1. 获取当前进程 ID
    DWORD main_process_id = GetCurrentProcessId();
    printf("Main process ID: %lu\n", main_process_id);
    
    // 2. 启动 Watchdog 的子进程来监护主程序
    // （实际中 Watchdog 通常是独立的进程或线程）
    
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    
    si.cb = sizeof(si);
    
    // 启动 Watchdog.exe，传入主程序的 PID
    char watchdog_cmd[512];
    snprintf(watchdog_cmd, sizeof(watchdog_cmd),
             "Watchdog.exe --target-pid %lu --check-interval 1000 --enable-tamper-detection",
             main_process_id);
    
    if (!CreateProcessA(NULL, watchdog_cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "Failed to launch Watchdog\n");
        return 1;
    }
    
    printf("Watchdog launched (PID: %lu)\n", pi.dwProcessId);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // 3. 主程序执行业务逻辑
    printf("\nMain program running...\n");
    printf("Watchdog is monitoring for:");
    printf("  - Process termination\n");
    printf("  - Debugger attachment\n");
    printf("  - Code tampering\n");
    printf("  - Memory modification\n");
    printf("\nPress Ctrl+C to exit normally\n\n");
    
    // 模拟长时间运行
    while (1) {
        printf("Main program working... (running for %.0f seconds)\n", 
               (double)GetTickCount() / 1000);
        Sleep(5000);
    }
    
    return 0;
}

/* ===== 另一个示例：直接使用 Watchdog API ===== */

int example_direct_watchdog_usage(void) {
    printf("=== Direct Watchdog API Usage ===\n\n");
    
    // 创建一个被监护的子进程（示例）
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    if (!CreateProcessA("target_program.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "Failed to create target process\n");
        return 1;
    }
    
    DWORD target_pid = pi.dwProcessId;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // 配置 Watchdog
    WatchdogConfig config = {0};
    config.target_process_id = target_pid;
    strcpy(config.target_process_name, "target_program.exe");
    config.check_interval_ms = 1000;           // 每 1 秒检查一次
    config.enable_tamper_detection = 1;        // 启用篡改检测
    config.enable_debug_mode = 1;              // 启用调试输出
    config.kernel_force_halt_enabled = 1;      // 启用内核级冻结
    strcpy(config.kernel_driver_path, "MTC_FS_Driver.sys");
    
    // 初始化 Watchdog
    WatchdogStatus status = Watchdog_Init(&config);
    if (status != WATCHDOG_OK) {
        fprintf(stderr, "Watchdog init failed: %d\n", status);
        return 1;
    }
    
    printf("Watchdog initialized for PID %lu\n", target_pid);
    
    // 启动监护
    status = Watchdog_Start();
    if (status != WATCHDOG_OK) {
        fprintf(stderr, "Watchdog start failed: %d\n", status);
        return 1;
    }
    
    printf("Watchdog monitoring started\n\n");
    
    // 监护运行
    while (1) {
        Sleep(2000);
        
        // 定期检查进程状态
        if (!Watchdog_IsTargetProcessAlive()) {
            printf("Target process is no longer alive\n");
            break;
        }
        
        // 执行篡改检测
        TamperDetectionResult tamper_result = {0};
        if (Watchdog_DetectTamper(&tamper_result) == WATCHDOG_OK) {
            if (tamper_result.is_debugger_attached) {
                printf("ALERT: Debugger detected!\n");
                // Watchdog 会自动处理
            }
        }
        
        printf("Process %lu is alive\n", target_pid);
    }
    
    // 停止 Watchdog
    Watchdog_Stop();
    printf("Watchdog stopped\n");
    
    return 0;
}

/* ===== 篡改检测示例 ===== */

void example_tamper_detection(DWORD target_pid) {
    printf("=== Tamper Detection Example ===\n\n");
    
    // 配置 Watchdog（不启动自动监护线程）
    WatchdogConfig config = {0};
    config.target_process_id = target_pid;
    config.enable_tamper_detection = 1;
    config.enable_debug_mode = 1;
    
    if (Watchdog_Init(&config) != WATCHDOG_OK) {
        fprintf(stderr, "Failed to init Watchdog\n");
        return;
    }
    
    // 定期进行主动篡改检测
    for (int i = 0; i < 10; i++) {
        printf("\n--- Check %d ---\n", i + 1);
        
        // 检测篡改
        TamperDetectionResult result = {0};
        if (Watchdog_DetectTamper(&result) == WATCHDOG_OK) {
            printf("Debugger attached: %s\n", result.is_debugger_attached ? "YES" : "NO");
            printf("Process suspended: %s\n", result.is_process_suspended ? "YES" : "NO");
            printf("Memory modified: %d pages\n", result.memory_pages_modified);
            
            if (result.tamper_reason[0]) {
                printf("Reason: %s\n", result.tamper_reason);
            }
        }
        
        // 获取代码段哈希
        unsigned char code_hash[32];
        if (Watchdog_GetProcessCodeHash(code_hash, sizeof(code_hash)) == WATCHDOG_OK) {
            printf("Code checksum: 0x%08X\n", *(unsigned int *)code_hash);
        }
        
        Sleep(3000);
    }
    
    Watchdog_Stop();
}
