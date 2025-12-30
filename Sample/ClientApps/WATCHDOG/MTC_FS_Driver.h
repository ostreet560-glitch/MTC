/*
 * ===== MTC Watchdog Kernel Driver Interface =====
 * 
 * 文件: MTC_FS_Driver.sys (未实现，需要自行开发)
 * 目的: 提供内核级的进程监控、篡改检测和强制系统冻结功能
 * 
 * 此文档定义了用户态 Watchdog 与内核驱动的通信协议
 */

#ifndef MTC_KERNEL_DRIVER_H
#define MTC_KERNEL_DRIVER_H

#include <ntdef.h>
#include <ntifs.h>
#include <ntstatus.h>

/* ===== IOCTL 定义 ===== */

// 强制系统冻结（触发蓝屏）
#define IOCTL_WATCHDOG_HALT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 查询监控状态
#define IOCTL_WATCHDOG_QUERY_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 注册目标进程监控
#define IOCTL_WATCHDOG_REGISTER_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 设置内存保护页面
#define IOCTL_WATCHDOG_PROTECT_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ===== 数据结构 ===== */

// 强制冻结参数
typedef struct {
    UCHAR reason[256];              // 冻结原因文本
} WATCHDOG_HALT_REQUEST;

// 监控状态查询
typedef struct {
    ULONG target_process_id;
    ULONG debugger_detected;        // 是否检测到调试器
    ULONG memory_tampering;         // 是否检测到内存篡改
    ULONG syscall_hooking;          // 是否检测到系统调用 Hook
} WATCHDOG_STATUS;

// 进程注册
typedef struct {
    ULONG process_id;
    UCHAR process_name[256];
    ULONG monitor_flags;            // 监控标志：0x01=调试器, 0x02=内存, 0x04=系统调用
} WATCHDOG_REGISTER_REQUEST;

// 内存保护
typedef struct {
    PVOID base_address;
    ULONG size;
    ULONG protect_mode;             // 0=只读, 1=执行, 2=禁止修改
} WATCHDOG_PROTECT_REQUEST;

/* ===== 驱动程序功能需求 ===== */

/*
 * 1. 进程事件监控
 *    - 创建/销毁事件回调
 *    - 线程创建/销毁监控
 *    - 模块加载事件
 * 
 * 2. 调试器检测 (Ring 0)
 *    - 检查 KPROCESS.DebugPort
 *    - 检查内核调试器状态
 *    - Hook KdInitSystem 检测调试器附加
 * 
 * 3. 内存保护与篡改检测
 *    - 使用 VAD（Virtual Address Descriptor）监控内存映射
 *    - Hook VirtualProtect/VirtualProtectEx 检测权限变更
 *    - 校验代码段完整性
 *    - 检测 DLL 注入
 * 
 * 4. 系统调用 Hook 检测
 *    - 枚举内核模块 IAT
 *    - 检测 SSDT（System Service Descriptor Table）被修改
 *    - 监控内核 Hook 框架（如 MinHook, Detours）
 * 
 * 5. 强制系统冻结
 *    - 调用 KeBugCheckEx 触发蓝屏
 *    - 参数: BugCheckCode = 0xDEADBEEF, 原因 = Watchdog 检测到篡改
 * 
 * 6. 通信接口
 *    - 实现 DriverEntry / DriverUnload
 *    - 创建设备对象 \\Device\\MTC_FS_Driver
 *    - 实现 IRP_MJ_DEVICE_CONTROL 处理程序
 *    - 使用 METHOD_BUFFERED 进行数据交互
 */

/* ===== 实现建议 ===== */

/*
 * 驱动框架:
 *
 * NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
 *     // 1. 创建设备对象
 *     UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\MTC_FS_Driver");
 *     IoCreateDevice(...);
 * 
 *     // 2. 注册 IRP 处理程序
 *     DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MTC_DeviceControl;
 * 
 *     // 3. 注册进程通知回调
 *     PsSetCreateProcessNotifyRoutineEx(MTC_ProcessNotify, FALSE);
 * 
 *     // 4. Hook 关键 API
 *     InstallHooks();
 * 
 *     return STATUS_SUCCESS;
 * }
 * 
 * NTSTATUS MTC_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
 *     PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
 *     ULONG ControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;
 * 
 *     switch (ControlCode) {
 *         case IOCTL_WATCHDOG_HALT:
 *             // 从 InputBuffer 读取原因，调用 KeBugCheckEx
 *             WATCHDOG_HALT_REQUEST *Request = (WATCHDOG_HALT_REQUEST *)Irp->AssociatedIrp.SystemBuffer;
 *             KeBugCheckEx(0xDEADBEEF, (ULONG_PTR)Request->reason, 0, 0, 0);
 *             break;
 *         case IOCTL_WATCHDOG_QUERY_STATUS:
 *             // 返回当前监控状态
 *             break;
 *         // ... 其他 IOCTL 处理
 *     }
 *     return STATUS_SUCCESS;
 * }
 */

/* ===== 安全考虑 ===== */

/*
 * 1. 权限验证
 *    - 仅允许 SYSTEM 权限的进程打开驱动设备
 *    - 验证来自用户态的请求合法性
 * 
 * 2. 反反调试
 *    - 定期检查自身代码完整性
 *    - 检测自身模块被 Hook/修改
 *    - 在检测到攻击时立即触发 BSOD
 * 
 * 3. 性能优化
 *    - 使用回调而非轮询
 *    - 避免频繁的用户态-内核态转换
 *    - 优化内存扫描算法
 */

#endif // MTC_KERNEL_DRIVER_H
