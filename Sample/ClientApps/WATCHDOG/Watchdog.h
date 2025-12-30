#ifndef WATCHDOG_H
#define WATCHDOG_H

#include <windows.h>
// 用户态版本：不依赖 WDK
#include "MTC_FS_Driver_UserMode.h"

/* ===== Watchdog 状态码 ===== */
typedef enum {
    WATCHDOG_OK = 0,
    WATCHDOG_INIT_FAILED = -1,
    WATCHDOG_DRIVER_NOT_FOUND = -2,
    WATCHDOG_DRIVER_COMM_ERROR = -3,
    WATCHDOG_PROCESS_TERMINATED = -4,
    WATCHDOG_TAMPER_DETECTED = -5,
    WATCHDOG_KERNEL_HALT_FAILED = -6
} WatchdogStatus;

/* ===== Watchdog 配置结构 ===== */
typedef struct {
    DWORD target_process_id;          // 要监护的主程序进程 ID
    char target_process_name[256];    // 进程名称，用于辅助识别
    DWORD check_interval_ms;          // 检查间隔（毫秒），默认 1000
    int enable_tamper_detection;      // 是否启用篡改检测
    int enable_debug_mode;            // 是否启用调试模式（verbose logging）
    int kernel_force_halt_enabled;    // 是否启用内核级强制冻结
    char kernel_driver_path[512];     // 内核驱动路径 (例如 "MTC_FS_Driver.sys")
} WatchdogConfig;

/* ===== 篡改检测结果 ===== */
typedef struct {
    int is_debugger_attached;         // 是否有调试器附加
    int is_process_suspended;         // 进程是否被挂起
    int memory_pages_modified;        // 内存页被修改（需内核支持）
    int code_section_altered;         // 代码段是否被篡改
    char tamper_reason[256];          // 篡改原因描述
} TamperDetectionResult;

/* ===== Watchdog 初始化 ===== */
// 初始化 Watchdog，建立与内核驱动的通信
// 参数: config - Watchdog 配置
// 返回: WATCHDOG_OK 成功，其他值表示失败
WatchdogStatus Watchdog_Init(WatchdogConfig *config);

/* ===== 启动监护线程 ===== */
// 启动独立线程监护目标进程
// 本函数返回后，Watchdog 在后台运行
// 返回: WATCHDOG_OK 成功，其他值表示失败
WatchdogStatus Watchdog_Start(void);

/* ===== 停止监护 ===== */
// 停止 Watchdog 监护（正常关闭）
// 返回: WATCHDOG_OK 成功
WatchdogStatus Watchdog_Stop(void);

/* ===== 获取监护状态 ===== */
// 检查目标进程是否仍在运行
// 返回: 1 - 进程正常运行，0 - 进程已终止，<0 - 错误
int Watchdog_IsTargetProcessAlive(void);

/* ===== 篡改检测 ===== */
// 执行一次完整的篡改检测
// 参数: result - 输出参数，包含检测结果
// 返回: WATCHDOG_OK 成功，其他值表示失败
WatchdogStatus Watchdog_DetectTamper(TamperDetectionResult *result);

/* ===== 获取进程内存快照用于校验 ===== */
// 获取目标进程代码段的哈希值（用于完整性验证）
// 参数: out_hash - 输出缓冲区（至少 32 字节用于 SHA256）
//       hash_len - 缓冲区长度
// 返回: WATCHDOG_OK 成功，其他值表示失败
WatchdogStatus Watchdog_GetProcessCodeHash(unsigned char *out_hash, int hash_len);

/* ===== 强制系统冻结（内核驱动调用） ===== */
// 触发内核驱动强制冻结系统（BSOD / Panic）
// 仅当启用 kernel_force_halt_enabled 时有效
// 返回: WATCHDOG_OK 成功，<0 表示失败
WatchdogStatus Watchdog_TriggerKernelHalt(const char *reason);

/* ===== 调试日志输出 ===== */
// Watchdog 内部日志输出
void Watchdog_DebugLog(const char *fmt, ...);

#endif // WATCHDOG_H
