/*
 * ===== MTC Watchdog User-Mode Driver Interface =====
 * 
 * 文件: MTC_FS_Driver_UserMode.h
 * 目的: 定义用户态程序与内核驱动通信所需的结构体和常量
 * 
 * 注意: 此头文件不依赖 Windows Driver Kit (WDK)，可在用户态编译环境中使用
 * 完整的驱动实现细节请见: MTC_FS_Driver.h (需要 WDK)
 */

#ifndef MTC_FS_DRIVER_USERMODE_H
#define MTC_FS_DRIVER_USERMODE_H

#include <windows.h>
#include <stddef.h>

/* ===== 版本控制 ===== */

#define MTC_DRIVER_API_VERSION          0x00010000  // Major.Minor = 1.0
#define MTC_DRIVER_API_MAJOR_VERSION    1
#define MTC_DRIVER_API_MINOR_VERSION    0

#define MTC_MIN_COMPATIBLE_VERSION      0x00010000  // 最低兼容版本

/* ===== 魔数与验证 ===== */

#define MTC_WATCHDOG_MAGIC              0xDEADBEEF  // 数据结构验证用
#define MTC_DEVICE_NAME_W               L"\\Device\\MTC_FS_Driver"
#define MTC_DEVICE_SYMLINK_W            L"\\??\\MTC_FS_Driver"
#define MTC_DEVICE_SYMLINK_A            "\\\\.\\MTC_FS_Driver"

/* ===== 错误代码定义 ===== */

typedef enum {
    WATCHDOG_OK                     = 0x00000000,
    WATCHDOG_ERR_INIT_FAILED        = 0x80000001,
    WATCHDOG_ERR_INVALID_PARAM      = 0x80000002,
    WATCHDOG_ERR_ACCESS_DENIED      = 0x80000003,
    WATCHDOG_ERR_PROCESS_NOT_FOUND  = 0x80000004,
    WATCHDOG_ERR_DRIVER_CORRUPTED   = 0x80000005,
    WATCHDOG_ERR_BUFFER_TOO_SMALL   = 0x80000006,
    WATCHDOG_ERR_ALREADY_REGISTERED = 0x80000007,
    WATCHDOG_ERR_TIMEOUT            = 0x80000008,
    WATCHDOG_ERR_INTERNAL           = 0x8000FFFF,
} WATCHDOG_RESULT;

/* ===== 监控标志定义 ===== */

#define WATCHDOG_FLAG_DEBUGGER_DETECTION    0x01
#define WATCHDOG_FLAG_MEMORY_PROTECTION     0x02
#define WATCHDOG_FLAG_SYSCALL_HOOK          0x04
#define WATCHDOG_FLAG_DLL_INJECTION         0x08
#define WATCHDOG_FLAG_PROCESS_CALLBACK      0x10
#define WATCHDOG_FLAG_THREAD_CALLBACK       0x20
#define WATCHDOG_FLAG_IMAGE_CALLBACK        0x40

#define WATCHDOG_FLAG_ALL               \
    (WATCHDOG_FLAG_DEBUGGER_DETECTION | \
     WATCHDOG_FLAG_MEMORY_PROTECTION | \
     WATCHDOG_FLAG_SYSCALL_HOOK | \
     WATCHDOG_FLAG_DLL_INJECTION | \
     WATCHDOG_FLAG_PROCESS_CALLBACK | \
     WATCHDOG_FLAG_THREAD_CALLBACK | \
     WATCHDOG_FLAG_IMAGE_CALLBACK)

/* ===== 内存保护模式 ===== */

#define WATCHDOG_PROTECT_READ_ONLY      0x04
#define WATCHDOG_PROTECT_EXECUTE        0x20
#define WATCHDOG_PROTECT_EXECUTE_READ   0x40
#define WATCHDOG_PROTECT_NO_ACCESS      0x01

/* ===== IOCTL 定义（用户态兼容版本） ===== */

// 自定义 CTL_CODE 宏（如果没有 winioctl.h）
#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

#define FILE_DEVICE_UNKNOWN             0x22
#define METHOD_BUFFERED                 0
#define FILE_ANY_ACCESS                 0

// 获取驱动版本信息
#define IOCTL_WATCHDOG_GET_VERSION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 初始化驱动监控参数
#define IOCTL_WATCHDOG_INITIALIZE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 注册目标进程监控
#define IOCTL_WATCHDOG_REGISTER_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 查询监控状态
#define IOCTL_WATCHDOG_QUERY_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 设置内存保护页面
#define IOCTL_WATCHDOG_PROTECT_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 强制系统冻结（触发蓝屏）
#define IOCTL_WATCHDOG_HALT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 卸载驱动清理资源
#define IOCTL_WATCHDOG_CLEANUP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ===== 数据结构（用户态版本） ===== */

// 版本信息
typedef struct {
    ULONG magic;                    // MTC_WATCHDOG_MAGIC
    ULONG api_version;              // MTC_DRIVER_API_VERSION
    ULONG driver_version;           // 驱动内部版本号
    unsigned char build_info[128];  // 构建信息字符串
    unsigned long long build_time;  // 构建时间戳
    ULONG reserved;
} WATCHDOG_VERSION_INFO;

// 驱动初始化参数
typedef struct {
    ULONG magic;                    // MTC_WATCHDOG_MAGIC (验证)
    ULONG initialization_flags;     // WATCHDOG_FLAG_* 组合
    ULONG timeout_ms;               // 操作超时时间 (单位: 毫秒)
    ULONG reserved[8];              // 预留字段
} WATCHDOG_INIT_REQUEST;

// 进程注册请求
typedef struct {
    ULONG magic;                    // MTC_WATCHDOG_MAGIC
    ULONG process_id;               // 目标进程 ID
    unsigned char process_name[256];// 进程文件名
    ULONG monitor_flags;            // 监控标志 (WATCHDOG_FLAG_*)
    unsigned long long registration_time;  // 注册时间
    ULONG reserved[4];              // 预留字段
} WATCHDOG_REGISTER_REQUEST;

// 监控状态查询响应
typedef struct {
    ULONG magic;                    // MTC_WATCHDOG_MAGIC
    ULONG target_process_id;        // 目标进程 ID
    ULONG status_flags;             // 0x01=调试器, 0x02=内存篡改, 0x04=系统调用 Hook
    unsigned long long last_check_time;  // 最后检查时间 (100ns 单位)
    ULONG last_violation_code;      // 上一次违规代码
    unsigned char last_violation_reason[256]; // 违规原因描述
    ULONG reserved[4];              // 预留字段
} WATCHDOG_STATUS;

// 内存保护请求
typedef struct {
    ULONG magic;                    // MTC_WATCHDOG_MAGIC
    void *base_address;             // 保护的基址
    unsigned long long size;        // 保护大小
    ULONG protect_mode;             // WATCHDOG_PROTECT_* 模式
    ULONG reserved[4];              // 预留字段
} WATCHDOG_PROTECT_REQUEST;

// 强制冻结请求
typedef struct {
    ULONG magic;                    // MTC_WATCHDOG_MAGIC
    unsigned char reason[256];      // 冻结原因文本
    ULONG error_code;               // 错误代码 (显示在蓝屏上)
    ULONG reserved[4];              // 预留字段
} WATCHDOG_HALT_REQUEST;

#endif // MTC_FS_DRIVER_USERMODE_H
