#include "Watchdog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

/* ===== 全局状态 ===== */
static WatchdogConfig g_watchdog_config = {0};
static int g_watchdog_initialized = 0;
static int g_watchdog_running = 0;
static HANDLE g_watchdog_thread = NULL;
static int g_debug_mode = 0;

/* ===== 内核驱动通信接口（预留） ===== */
// 注：实际部署时需要：
// 1. 编写内核驱动 (MTC_FS_Driver.sys)
// 2. 驱动需实现以下功能：
//    - 监控进程创建/终止事件
//    - 检测 Kernel Debugger 附加
//    - Hook 系统调用以检测篡改
//    - 提供强制 BSOD 接口
// 3. 通过 DeviceIoControl 与用户态通信

#define KERNEL_DRIVER_NAME              "\\\\.\\MTC_FS_Driver"

static HANDLE g_kernel_driver_handle = NULL;

/* ===== 内核驱动通信 ===== */
static int Watchdog_OpenKernelDriver(void) {
    if (g_kernel_driver_handle != NULL) return 1;
    
    g_kernel_driver_handle = CreateFileA(
        KERNEL_DRIVER_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (g_kernel_driver_handle == INVALID_HANDLE_VALUE) {
        Watchdog_DebugLog("Failed to open kernel driver");
        g_kernel_driver_handle = NULL;
        return 0;
    }
    
    Watchdog_DebugLog("Kernel driver connected");
    return 1;
}

static void Watchdog_CloseKernelDriver(void) {
    if (g_kernel_driver_handle) {
        CloseHandle(g_kernel_driver_handle);
        g_kernel_driver_handle = NULL;
    }
}

/* ===== 进程活性检查 ===== */
static int Watchdog_CheckProcessAlive(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (process == NULL) return 0;
    
    DWORD exit_code;
    int alive = GetExitCodeProcess(process, &exit_code) && (exit_code == STILL_ACTIVE);
    
    CloseHandle(process);
    return alive;
}

/* ===== 调试器检测 ===== */
static int Watchdog_IsDebuggerAttached(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process) return 0;
    
    BOOL is_debugged = FALSE;
    CheckRemoteDebuggerPresent(process, &is_debugged);
    
    CloseHandle(process);
    return is_debugged ? 1 : 0;
}

/* ===== 计算进程代码段哈希（简化版） ===== */
// 注：实际实现应使用 CryptAPI 计算 SHA256
// 这里用简单的校验和作为演示
static unsigned int Watchdog_SimpleChecksum(unsigned char *data, int len) {
    unsigned int sum = 0;
    for (int i = 0; i < len; i++) {
        sum = ((sum << 5) + sum) ^ data[i];  // sum * 33 XOR byte
    }
    return sum;
}

/* ===== 监护线程主循环 ===== */
static DWORD WINAPI Watchdog_ThreadProc(LPVOID param) {
    Watchdog_DebugLog("Watchdog thread started, monitoring PID %lu", g_watchdog_config.target_process_id);
    
    while (g_watchdog_running) {
        // 1. 检查目标进程是否存活
        if (!Watchdog_CheckProcessAlive(g_watchdog_config.target_process_id)) {
            Watchdog_DebugLog("Target process %lu terminated!", g_watchdog_config.target_process_id);
            
            // 进程被终止，触发系统冻结
            if (g_watchdog_config.kernel_force_halt_enabled) {
                Watchdog_TriggerKernelHalt("Target process terminated unexpectedly");
            } else {
                Watchdog_DebugLog("Kernel halt disabled, emergency exit");
                exit(255);  // 紧急退出
            }
            break;
        }
        
        // 2. 篡改检测
        if (g_watchdog_config.enable_tamper_detection) {
            TamperDetectionResult tamper_result = {0};
            
            // 检测调试器
            if (Watchdog_IsDebuggerAttached(g_watchdog_config.target_process_id)) {
                tamper_result.is_debugger_attached = 1;
                strcpy(tamper_result.tamper_reason, "Debugger detected");
                
                Watchdog_DebugLog("ALERT: Debugger attached to target process!");
                
                if (g_watchdog_config.kernel_force_halt_enabled) {
                    Watchdog_TriggerKernelHalt("Debugger attachment detected");
                } else {
                    exit(254);
                }
                break;
            }
            
            // TODO: 更多篡改检测
            // - 代码段完整性校验
            // - 内存页保护状态检查
            // - 系统调用 Hook 检测（需内核支持）
        }
        
        // 3. 定期检查
        Sleep(g_watchdog_config.check_interval_ms);
    }
    
    Watchdog_DebugLog("Watchdog thread exiting");
    return 0;
}

/* ===== 公开函数实现 ===== */

WatchdogStatus Watchdog_Init(WatchdogConfig *config) {
    if (!config || config->target_process_id == 0) {
        fprintf(stderr, "Invalid Watchdog config\n");
        return WATCHDOG_INIT_FAILED;
    }
    
    memcpy(&g_watchdog_config, config, sizeof(WatchdogConfig));
    g_debug_mode = config->enable_debug_mode;
    
    // 如果启用内核驱动，尝试打开连接
    if (config->kernel_force_halt_enabled) {
        if (!Watchdog_OpenKernelDriver()) {
            Watchdog_DebugLog("Warning: Kernel driver not available, fallback to user-mode halt");
            // 这里可以选择降级处理或直接失败
        }
    }
    
    g_watchdog_initialized = 1;
    Watchdog_DebugLog("Watchdog initialized for PID %lu", config->target_process_id);
    
    return WATCHDOG_OK;
}

WatchdogStatus Watchdog_Start(void) {
    if (!g_watchdog_initialized) {
        return WATCHDOG_INIT_FAILED;
    }
    
    if (g_watchdog_running) {
        return WATCHDOG_OK;  // Already running
    }
    
    g_watchdog_running = 1;
    g_watchdog_thread = CreateThread(
        NULL,
        0,
        Watchdog_ThreadProc,
        NULL,
        0,
        NULL
    );
    
    if (!g_watchdog_thread) {
        g_watchdog_running = 0;
        return WATCHDOG_INIT_FAILED;
    }
    
    Watchdog_DebugLog("Watchdog monitoring started");
    return WATCHDOG_OK;
}

WatchdogStatus Watchdog_Stop(void) {
    if (!g_watchdog_running) return WATCHDOG_OK;
    
    g_watchdog_running = 0;
    
    if (g_watchdog_thread) {
        WaitForSingleObject(g_watchdog_thread, 5000);  // 等待 5 秒
        CloseHandle(g_watchdog_thread);
        g_watchdog_thread = NULL;
    }
    
    Watchdog_CloseKernelDriver();
    
    Watchdog_DebugLog("Watchdog stopped");
    return WATCHDOG_OK;
}

int Watchdog_IsTargetProcessAlive(void) {
    if (!g_watchdog_initialized) return -1;
    return Watchdog_CheckProcessAlive(g_watchdog_config.target_process_id);
}

WatchdogStatus Watchdog_DetectTamper(TamperDetectionResult *result) {
    if (!result) return WATCHDOG_INIT_FAILED;
    
    memset(result, 0, sizeof(TamperDetectionResult));
    
    DWORD pid = g_watchdog_config.target_process_id;
    
    // 调试器检测
    result->is_debugger_attached = Watchdog_IsDebuggerAttached(pid);
    
    // 进程状态检查
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) {
        strcpy(result->tamper_reason, "Cannot access process");
        return WATCHDOG_DRIVER_COMM_ERROR;
    }
    
    // TODO: 更多检测逻辑（需内核支持）
    // - 枚举线程状态
    // - 读取内存校验
    // - 检查 PEB/TEB 完整性
    
    CloseHandle(process);
    
    return WATCHDOG_OK;
}

WatchdogStatus Watchdog_GetProcessCodeHash(unsigned char *out_hash, int hash_len) {
    if (!out_hash || hash_len < 4) return WATCHDOG_INIT_FAILED;
    
    // 简化版：使用校验和而非真实 SHA256
    // 实际部署应使用 CryptAPI 计算真实 SHA256
    
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, 
                                  g_watchdog_config.target_process_id);
    if (!process) return WATCHDOG_DRIVER_COMM_ERROR;
    
    // 读取 PE 头获取代码段信息
    unsigned char pe_header[1024] = {0};
    SIZE_T bytes_read = 0;
    ReadProcessMemory(process, (LPVOID)0x400000, pe_header, sizeof(pe_header), &bytes_read);
    
    if (bytes_read > 0) {
        unsigned int checksum = Watchdog_SimpleChecksum(pe_header, bytes_read);
        *(unsigned int *)out_hash = checksum;
    }
    
    CloseHandle(process);
    return WATCHDOG_OK;
}

WatchdogStatus Watchdog_TriggerKernelHalt(const char *reason) {
    Watchdog_DebugLog("FATAL: Triggering system halt - %s", reason ? reason : "unknown reason");
    
    if (g_kernel_driver_handle) {
        // 通过内核驱动触发 BSOD
        WATCHDOG_HALT_REQUEST halt_req = {0};
        halt_req.magic = MTC_WATCHDOG_MAGIC;
        strncpy((char *)halt_req.reason, reason ? reason : "Unknown", sizeof(halt_req.reason) - 1);
        halt_req.error_code = 0xDEADBEEF;
        
        DWORD bytes_returned = 0;
        BOOL result = DeviceIoControl(
            g_kernel_driver_handle,
            IOCTL_WATCHDOG_HALT,
            &halt_req,
            sizeof(halt_req),
            NULL,
            0,
            &bytes_returned,
            NULL
        );
        
        if (result) {
            Watchdog_DebugLog("Kernel halt command sent successfully");
            Sleep(INFINITE);  // 等待内核冻结系统
            return WATCHDOG_OK;
        } else {
            Watchdog_DebugLog("Kernel halt command failed, fallback to user-mode exit");
        }
    }
    
    // 用户态降级方案：强制系统关闭
    system("shutdown /s /f /t 1 /c \"MTC Watchdog: System integrity violation\"");
    Sleep(INFINITE);
    
    return WATCHDOG_KERNEL_HALT_FAILED;
}

void Watchdog_DebugLog(const char *fmt, ...) {
    if (!g_debug_mode) return;
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    printf("[Watchdog %s] ", time_str);
    
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    
    printf("\n");
}
