/*
 * ===== MTC Watchdog Kernel Driver Interface =====
 * 
 * 文件: MTC_FS_Driver.sys (未实现，需要自行开发)
 * 目的: 提供内核级的进程监控、篡改检测和强制系统冻结功能
 * 
 * 此文档定义了用户态 Watchdog 与内核驱动的通信协议
 * 版本: 1.0
 * 作者: MTC Project
 */

#ifndef MTC_KERNEL_DRIVER_H
#define MTC_KERNEL_DRIVER_H

#include <ntdef.h>
#include <ntifs.h>
#include <ntstatus.h>

/* ===== 版本控制 ===== */

#define MTC_DRIVER_API_VERSION          0x00010000  // Major.Minor = 1.0
#define MTC_DRIVER_API_MAJOR_VERSION    1
#define MTC_DRIVER_API_MINOR_VERSION    0

#define MTC_MIN_COMPATIBLE_VERSION      0x00010000  // 最低兼容版本

/* ===== 魔数与验证 ===== */

#define MTC_WATCHDOG_MAGIC              0xDEADBEEF  // 数据结构验证用
#define MTC_DEVICE_NAME                 L"\\Device\\MTC_FS_Driver"
#define MTC_DEVICE_SYMLINK              L"\\??\\MTC_FS_Driver"
#define MTC_DEVICE_SECURITY_DESCRIPTOR  L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"  // SYSTEM, Administrators only

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

#define WATCHDOG_PROTECT_READ_ONLY      PAGE_READONLY
#define WATCHDOG_PROTECT_EXECUTE        PAGE_EXECUTE
#define WATCHDOG_PROTECT_EXECUTE_READ   PAGE_EXECUTE_READ
#define WATCHDOG_PROTECT_NO_ACCESS      PAGE_NOACCESS

/* ===== IOCTL 定义 ===== */

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

/* ===== 数据结构 ===== */

// 版本信息
typedef struct {
    ULONG magic;                    // MTC_WATCHDOG_MAGIC
    ULONG api_version;              // MTC_DRIVER_API_VERSION
    ULONG driver_version;           // 驱动内部版本号
    UCHAR build_info[128];          // 构建信息字符串
    ULONGLONG build_time;           // 构建时间戳
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
    UCHAR process_name[256];        // 进程文件名
    ULONG monitor_flags;            // 监控标志 (WATCHDOG_FLAG_*)
    ULONGLONG registration_time;    // 注册时间
    ULONG reserved[4];              // 预留字段
} WATCHDOG_REGISTER_REQUEST;

// 监控状态查询响应
typedef struct {
    ULONG magic;                    // MTC_WATCHDOG_MAGIC
    ULONG target_process_id;        // 目标进程 ID
    ULONG status_flags;             // 0x01=调试器, 0x02=内存篡改, 0x04=系统调用 Hook
    ULONGLONG last_check_time;      // 最后检查时间 (100ns 单位)
    ULONG last_violation_code;      // 上一次违规代码
    UCHAR last_violation_reason[256]; // 违规原因描述
    ULONG reserved[4];              // 预留字段
} WATCHDOG_STATUS;

// 内存保护请求
typedef struct {
    ULONG magic;                    // MTC_WATCHDOG_MAGIC
    PVOID base_address;             // 保护的基址
    ULONGLONG size;                 // 保护大小
    ULONG protect_mode;             // WATCHDOG_PROTECT_* 模式
    ULONG reserved[4];              // 预留字段
} WATCHDOG_PROTECT_REQUEST;

// 强制冻结请求
typedef struct {
    ULONG magic;                    // MTC_WATCHDOG_MAGIC
    UCHAR reason[256];              // 冻结原因文本
    ULONG error_code;               // 错误代码 (显示在蓝屏上)
    ULONG reserved[4];              // 预留字段
} WATCHDOG_HALT_REQUEST;

/* ===== 驱动程序功能需求 ===== */

/*
 * 1. 进程事件监控
 *    - PsSetCreateProcessNotifyRoutineEx - 创建/销毁事件回调
 *    - PsSetCreateThreadNotifyRoutine - 线程创建/销毁监控
 *    - PsSetLoadImageNotifyRoutine - 模块加载事件
 * 
 * 2. 调试器检测 (Ring 0)
 *    - 检查 KPROCESS.DebugPort (偏移量: Win10 x64 = 0x2F8)
 *    - 检查内核调试器状态 (KdDebuggerEnabled)
 *    - Hook KdInitSystem 检测调试器附加
 * 
 * 3. 内存保护与篡改检测
 *    - 使用 VAD（Virtual Address Descriptor）监控内存映射
 *    - Hook NtProtectVirtualMemory 检测权限变更
 *    - 校验代码段 (.text) 完整性
 *    - 检测 DLL 注入 (通过 NtMapViewOfSection)
 * 
 * 4. 系统调用 Hook 检测
 *    - 枚举内核模块 IAT
 *    - 检测 SSDT（System Service Descriptor Table）被修改
 *    - 监控内核 Hook 框架（如 MinHook, Detours）
 *    - 检查关键函数地址是否在合法范围内
 * 
 * 5. 强制系统冻结
 *    - 调用 KeBugCheckEx 触发蓝屏
 *    - BugCheckCode = 0xDEADBEEF
 *    - 参数1 = 冻结原因字符串
 *    - 不会返回到调用者
 * 
 * 6. 通信接口
 *    - 实现 DriverEntry / DriverUnload
 *    - 创建设备对象 (MTC_DEVICE_NAME)
 *    - 实现 IRP_MJ_DEVICE_CONTROL 处理程序
 *    - 使用 METHOD_BUFFERED 进行数据交互
 *    - 验证所有输入参数 (magic 字段，缓冲区大小)
 */

/* ===== 驱动框架框图 ===== */

/*
 * 完整的 DriverEntry 实现框架：
 *
 * NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
 *     NTSTATUS Status = STATUS_SUCCESS;
 *     UNICODE_STRING DeviceName, SymbolicName;
 *     PDEVICE_OBJECT DeviceObject = NULL;
 *
 *     KdPrint(("[MTC] DriverEntry started\n"));
 *
 *     // 1. 创建设备对象
 *     RtlInitUnicodeString(&DeviceName, MTC_DEVICE_NAME);
 *     Status = IoCreateDevice(
 *         DriverObject,
 *         0,
 *         &DeviceName,
 *         FILE_DEVICE_UNKNOWN,
 *         FILE_DEVICE_SECURE_OPEN,
 *         FALSE,
 *         &DeviceObject
 *     );
 *
 *     if (!NT_SUCCESS(Status)) {
 *         KdPrint(("[MTC] IoCreateDevice failed: 0x%X\n", Status));
 *         return Status;
 *     }
 *
 *     // 2. 创建符号链接（用户态访问）
 *     RtlInitUnicodeString(&SymbolicName, MTC_DEVICE_SYMLINK);
 *     Status = IoCreateSymbolicLink(&SymbolicName, &DeviceName);
 *
 *     if (!NT_SUCCESS(Status)) {
 *         IoDeleteDevice(DeviceObject);
 *         return Status;
 *     }
 *
 *     // 3. 设置设备安全描述符
 *     UNICODE_STRING SdString;
 *     RtlInitUnicodeString(&SdString, MTC_DEVICE_SECURITY_DESCRIPTOR);
 *     // 使用 WinAPI 或驱动 API 设置 ACL (仅 SYSTEM 和 Administrators)
 *
 *     // 4. 注册 IRP 处理程序
 *     DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MTC_DeviceControl;
 *     DriverObject->MajorFunction[IRP_MJ_CREATE] = MTC_Create;
 *     DriverObject->MajorFunction[IRP_MJ_CLOSE] = MTC_Close;
 *     DriverObject->DriverUnload = MTC_DriverUnload;
 *
 *     // 5. 注册进程通知回调
 *     Status = PsSetCreateProcessNotifyRoutineEx(MTC_ProcessNotify, FALSE);
 *     if (!NT_SUCCESS(Status)) {
 *         KdPrint(("[MTC] PsSetCreateProcessNotifyRoutineEx failed: 0x%X\n", Status));
 *         // 继续，不返回错误
 *     }
 *
 *     // 6. 注册线程通知回调
 *     Status = PsSetCreateThreadNotifyRoutine(MTC_ThreadNotify);
 *     if (!NT_SUCCESS(Status)) {
 *         KdPrint(("[MTC] PsSetCreateThreadNotifyRoutine failed: 0x%X\n", Status));
 *     }
 *
 *     // 7. 初始化全局驱动上下文
 *     // ...
 *
 *     DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
 *     KdPrint(("[MTC] DriverEntry completed successfully\n"));
 *     return STATUS_SUCCESS;
 * }
 */

/* ===== IRP_MJ_DEVICE_CONTROL 处理框架 ===== */

/*
 * NTSTATUS MTC_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
 *     NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;
 *     PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
 *     ULONG ControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;
 *     PVOID InputBuffer = Irp->AssociatedIrp.SystemBuffer;
 *     ULONG InputLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
 *     ULONG OutputLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
 *
 *     KdPrint(("[MTC] DeviceControl: 0x%X\n", ControlCode));
 *
 *     // 验证输入缓冲区
 *     if (!InputBuffer || InputLength == 0) {
 *         Status = STATUS_INVALID_PARAMETER;
 *         goto Cleanup;
 *     }
 *
 *     switch (ControlCode) {
 *         case IOCTL_WATCHDOG_GET_VERSION: {
 *             // 返回驱动版本信息
 *             if (OutputLength < sizeof(WATCHDOG_VERSION_INFO)) {
 *                 Status = STATUS_BUFFER_TOO_SMALL;
 *                 break;
 *             }
 *
 *             PWATCHDOG_VERSION_INFO VersionInfo = 
 *                 (PWATCHDOG_VERSION_INFO)Irp->AssociatedIrp.SystemBuffer;
 *
 *             VersionInfo->magic = MTC_WATCHDOG_MAGIC;
 *             VersionInfo->api_version = MTC_DRIVER_API_VERSION;
 *             VersionInfo->driver_version = 0x00010000;
 *             strcpy(VersionInfo->build_info, "MTC Watchdog v1.0");
 *             VersionInfo->build_time = __TIMESTAMP__;
 *
 *             Irp->IoStatus.Information = sizeof(WATCHDOG_VERSION_INFO);
 *             Status = STATUS_SUCCESS;
 *             break;
 *         }
 *
 *         case IOCTL_WATCHDOG_HALT: {
 *             // 验证输入大小
 *             if (InputLength < sizeof(WATCHDOG_HALT_REQUEST)) {
 *                 Status = STATUS_INVALID_PARAMETER;
 *                 break;
 *             }
 *
 *             PWATCHDOG_HALT_REQUEST Request = (PWATCHDOG_HALT_REQUEST)InputBuffer;
 *
 *             // 验证魔数
 *             if (Request->magic != MTC_WATCHDOG_MAGIC) {
 *                 Status = STATUS_INVALID_PARAMETER;
 *                 break;
 *             }
 *
 *             KdPrint(("[MTC] Triggering BSOD: %s (0x%X)\n", 
 *                      Request->reason, Request->error_code));
 *
 *             // 触发 BSOD - 此函数不返回
 *             KeBugCheckEx(
 *                 0xDEADBEEF,
 *                 (ULONG_PTR)Request->reason,
 *                 Request->error_code,
 *                 0,
 *                 0
 *             );
 *             // 此处不会执行
 *             break;
 *         }
 *
 *         case IOCTL_WATCHDOG_QUERY_STATUS: {
 *             // 查询当前监控状态
 *             if (OutputLength < sizeof(WATCHDOG_STATUS)) {
 *                 Status = STATUS_BUFFER_TOO_SMALL;
 *                 break;
 *             }
 *
 *             PWATCHDOG_STATUS StatusInfo = 
 *                 (PWATCHDOG_STATUS)Irp->AssociatedIrp.SystemBuffer;
 *
 *             StatusInfo->magic = MTC_WATCHDOG_MAGIC;
 *             StatusInfo->target_process_id = HandleToUlong(PsGetCurrentProcessId());
 *             StatusInfo->status_flags = MTC_QueryCurrentStatus();
 *             StatusInfo->last_check_time = KeQuerySystemTime().QuadPart;
 *             // ... 填充其他字段
 *
 *             Irp->IoStatus.Information = sizeof(WATCHDOG_STATUS);
 *             Status = STATUS_SUCCESS;
 *             break;
 *         }
 *
 *         case IOCTL_WATCHDOG_REGISTER_PROCESS: {
 *             // 注册监控目标进程
 *             if (InputLength < sizeof(WATCHDOG_REGISTER_REQUEST)) {
 *                 Status = STATUS_INVALID_PARAMETER;
 *                 break;
 *             }
 *
 *             PWATCHDOG_REGISTER_REQUEST Request = 
 *                 (PWATCHDOG_REGISTER_REQUEST)InputBuffer;
 *
 *             if (Request->magic != MTC_WATCHDOG_MAGIC) {
 *                 Status = STATUS_INVALID_PARAMETER;
 *                 break;
 *             }
 *
 *             Status = MTC_RegisterProcessMonitoring(
 *                 Request->process_id,
 *                 Request->process_name,
 *                 Request->monitor_flags
 *             );
 *
 *             Irp->IoStatus.Information = 0;
 *             break;
 *         }
 *
 *         default:
 *             Status = STATUS_INVALID_DEVICE_REQUEST;
 *             break;
 *     }
 *
 * Cleanup:
 *     Irp->IoStatus.Status = Status;
 *     IoCompleteRequest(Irp, IO_NO_INCREMENT);
 *     return Status;
 * }
 */


/* ===== 安全最佳实践 ===== */

/*
 * 1. 输入验证
 *    - 所有输入缓冲区都必须验证 magic 字段 (MTC_WATCHDOG_MAGIC)
 *    - 检查缓冲区大小，防止缓冲区溢出
 *    - 验证指针有效性 (ProbeForRead / ProbeForWrite)
 *    - 检查字符串是否以 NULL 结尾
 *
 * 2. 权限与访问控制
 *    - 在 IRP_MJ_CREATE 时验证调用方身份 (SeAccessCheck)
 *    - 仅允许 SYSTEM 或 ADMIN 权限的进程
 *    - 设置设备 ACL: "D:P(A;;GA;;;SY)(A;;GA;;;BA)" (SYSTEM, Administrators)
 *    - 不允许未授权用户终止驱动或关闭设备
 *
 * 3. 反反调试与自保护
 *    - 定期计算驱动代码段校验和，检测 Hook/修改
 *    - 监控 SSDT 防止自身被 Hook
 *    - 在驱动自身被篡改时立即触发 BSOD
 *    - 禁止调试器附加到驱动
 *
 * 4. 错误处理与容错
 *    - 所有系统调用返回值都必须检查 (NT_SUCCESS)
 *    - 异常情况使用 try-except 或 __try-__except
 *    - 避免 Panic，使用状态码返回错误
 *    - 记录所有异常事件到系统日志
 *
 * 5. 内存管理
 *    - 使用 NonPagedPool 分配内存（驱动上下文）
 *    - 及时释放申请的内存，防止泄漏
 *    - 使用 POOL_NX_OPTIN 启用 No-Execute (NX) 保护
 *    - 初始化所有内存结构，避免未初始化值
 *
 * 6. 性能考虑
 *    - 使用回调而非轮询（进程事件、线程事件）
 *    - 避免频繁的用户态-内核态转换
 *    - Hook 的 Hot Path 应尽可能精简
 *    - 使用旋转锁 (Spinlock) 保护共享数据，避免死锁
 *
 * 7. 驱动卸载与清理
 *    - 实现 DriverUnload 例程
 *    - 注销所有回调 (PsRemoveCreateProcessNotifyRoutineEx)
 *    - 关闭所有打开的句柄和资源
 *    - 释放分配的内存
 *    - 删除符号链接和设备对象
 */

/* ===== 调用示例（用户态）===== */

/*
 * 用户态程序调用驱动的示例：
 *
 * #include "MTC_FS_Driver.h"
 * #include <windows.h>
 *
 * void Example_QueryVersion(void) {
 *     HANDLE hDevice = CreateFileA(
 *         "\\\\.\\MTC_FS_Driver",
 *         GENERIC_READ | GENERIC_WRITE,
 *         0,
 *         NULL,
 *         OPEN_EXISTING,
 *         FILE_ATTRIBUTE_NORMAL,
 *         NULL
 *     );
 *
 *     if (hDevice == INVALID_HANDLE_VALUE) {
 *         printf("Failed to open driver: %lu\n", GetLastError());
 *         return;
 *     }
 *
 *     WATCHDOG_VERSION_INFO VersionInfo = {0};
 *     DWORD BytesReturned = 0;
 *
 *     BOOL Result = DeviceIoControl(
 *         hDevice,
 *         IOCTL_WATCHDOG_GET_VERSION,
 *         NULL,
 *         0,
 *         &VersionInfo,
 *         sizeof(VersionInfo),
 *         &BytesReturned,
 *         NULL
 *     );
 *
 *     if (Result && VersionInfo.magic == MTC_WATCHDOG_MAGIC) {
 *         printf("Driver API Version: 0x%X\n", VersionInfo.api_version);
 *         printf("Build Info: %s\n", VersionInfo.build_info);
 *     } else {
 *         printf("Failed to query version: %lu\n", GetLastError());
 *     }
 *
 *     CloseHandle(hDevice);
 * }
 *
 * void Example_RegisterProcess(void) {
 *     HANDLE hDevice = CreateFileA(
 *         "\\\\.\\MTC_FS_Driver",
 *         GENERIC_READ | GENERIC_WRITE,
 *         0,
 *         NULL,
 *         OPEN_EXISTING,
 *         FILE_ATTRIBUTE_NORMAL,
 *         NULL
 *     );
 *
 *     if (hDevice == INVALID_HANDLE_VALUE) {
 *         return;
 *     }
 *
 *     WATCHDOG_REGISTER_REQUEST RegisterReq = {0};
 *     RegisterReq.magic = MTC_WATCHDOG_MAGIC;
 *     RegisterReq.process_id = GetCurrentProcessId();
 *     strcpy((char *)RegisterReq.process_name, "myapp.exe");
 *     RegisterReq.monitor_flags = WATCHDOG_FLAG_ALL;
 *     RegisterReq.registration_time = GetTickCount64();
 *
 *     DWORD BytesReturned = 0;
 *     BOOL Result = DeviceIoControl(
 *         hDevice,
 *         IOCTL_WATCHDOG_REGISTER_PROCESS,
 *         &RegisterReq,
 *         sizeof(RegisterReq),
 *         NULL,
 *         0,
 *         &BytesReturned,
 *         NULL
 *     );
 *
 *     if (!Result) {
 *         printf("Failed to register process: %lu\n", GetLastError());
 *     }
 *
 *     CloseHandle(hDevice);
 * }
 */

#endif // MTC_KERNEL_DRIVER_H
