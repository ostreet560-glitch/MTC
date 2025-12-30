# MTC 内核驱动开发指南

## 概述

MTC 内核驱动 `MTC_FS_Driver.sys` 提供 Ring 0 级别的安全防护，是 Watchdog 系统的可选但强大的扩展。

**主要职责：**
- 进程事件监控（创建、销毁、异常）
- 调试器检测（Ring 0 级别）
- 内存保护与篡改检测
- 系统调用 Hook 检测
- 强制 BSOD 触发

---

## 开发环境

### 所需工具

1. **Windows Driver Kit (WDK)**
   - 下载: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
   - 版本: Windows 10 / 11 WDK

2. **Visual Studio**
   - 推荐: Visual Studio 2019 或更新
   - 工作负荷: "Desktop development with C++" + WDK

3. **代码签名证书** (可选，开发时可用测试证书)

### 环境配置

```bash
# 安装 WDK
# 1. 下载 WDK ISO
# 2. 挂载 ISO，运行 wdksetup.exe
# 3. 选择完整安装

# 验证安装
where msbuild
where cl.exe
where signtool.exe
```

---

## 驱动框架

### 基础结构

```c
#include <ntdef.h>
#include <ntifs.h>
#include <ntstatus.h>

// IOCTL 定义（与 Watchdog.h 保持一致）
#define IOCTL_WATCHDOG_HALT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WATCHDOG_QUERY_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WATCHDOG_REGISTER_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 驱动数据结构
typedef struct {
    PDEVICE_OBJECT DeviceObject;
    PDRIVER_OBJECT DriverObject;
    PVOID ProcessNotifyHandle;
    PVOID ThreadNotifyHandle;
    // ... 其他全局状态
} DRIVER_CONTEXT;

static DRIVER_CONTEXT g_driver_context = {0};
```

### DriverEntry - 驱动入口

```c
#pragma code_seg("INIT")

NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
) {
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymbolicName;
    PDEVICE_OBJECT DeviceObject = NULL;

    KdPrint(("[MTC] DriverEntry started\n"));

    // 1. 创建设备对象
    RtlInitUnicodeString(&DeviceName, L"\\Device\\MTC_FS_Driver");
    Status = IoCreateDevice(
        DriverObject,
        sizeof(DRIVER_CONTEXT),  // DeviceExtension size
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &DeviceObject
    );

    if (!NT_SUCCESS(Status)) {
        KdPrint(("[MTC] IoCreateDevice failed: 0x%X\n", Status));
        return Status;
    }

    // 2. 创建符号链接（用户态访问）
    RtlInitUnicodeString(&SymbolicName, L"\\??\\MTC_FS_Driver");
    Status = IoCreateSymbolicLink(&SymbolicName, &DeviceName);

    if (!NT_SUCCESS(Status)) {
        KdPrint(("[MTC] IoCreateSymbolicLink failed: 0x%X\n", Status));
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    // 3. 注册 IRP 处理程序
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MTC_DeviceControl;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = MTC_Create;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = MTC_Close;
    DriverObject->DriverUnload = MTC_DriverUnload;

    // 4. 注册进程通知回调
    Status = PsSetCreateProcessNotifyRoutineEx(MTC_ProcessNotify, FALSE);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("[MTC] PsSetCreateProcessNotifyRoutineEx failed: 0x%X\n", Status));
    }

    // 5. 注册线程通知回调（可选）
    Status = PsSetCreateThreadNotifyRoutine(MTC_ThreadNotify);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("[MTC] PsSetCreateThreadNotifyRoutine failed: 0x%X\n", Status));
    }

    // 6. 初始化驱动上下文
    PDRIVER_CONTEXT Context = (PDRIVER_CONTEXT)DeviceObject->DeviceExtension;
    Context->DeviceObject = DeviceObject;
    Context->DriverObject = DriverObject;
    Context->ProcessNotifyHandle = NULL;
    Context->ThreadNotifyHandle = NULL;

    // 7. 设置设备标志
    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    KdPrint(("[MTC] DriverEntry completed successfully\n"));
    return STATUS_SUCCESS;
}

#pragma code_seg()
```

### DeviceControl - IRP 处理

```c
NTSTATUS MTC_DeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
) {
    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;

    PVOID InputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG InputLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

    KdPrint(("[MTC] DeviceControl: 0x%X\n", ControlCode));

    switch (ControlCode) {
        case IOCTL_WATCHDOG_HALT: {
            // 强制 BSOD
            const char *reason = (const char *)InputBuffer;
            KdPrint(("[MTC] Triggering BSOD: %s\n", reason));

            // 不会返回
            KeBugCheckEx(
                0xDEADBEEF,                    // BugCheckCode
                (ULONG_PTR)reason,             // BugCheckParameter1
                0,
                0,
                0
            );
            // 此处不会执行
            break;
        }

        case IOCTL_WATCHDOG_QUERY_STATUS: {
            // 查询监控状态
            if (OutputLength >= sizeof(WATCHDOG_STATUS)) {
                PWATCHDOG_STATUS Status = (PWATCHDOG_STATUS)Irp->AssociatedIrp.SystemBuffer;

                Status->target_process_id = GetCurrentProcessId();
                Status->debugger_detected = MTC_IsDebuggerAttached();
                Status->memory_tampering = MTC_DetectMemoryTampering();
                Status->syscall_hooking = MTC_DetectSyscallHooking();

                Irp->IoStatus.Information = sizeof(WATCHDOG_STATUS);
                Status = STATUS_SUCCESS;
            } else {
                Status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }

        case IOCTL_WATCHDOG_REGISTER_PROCESS: {
            // 注册目标进程进行监控
            if (InputLength >= sizeof(WATCHDOG_REGISTER_REQUEST)) {
                PWATCHDOG_REGISTER_REQUEST Request = 
                    (PWATCHDOG_REGISTER_REQUEST)InputBuffer;

                Status = MTC_RegisterProcessMonitoring(
                    Request->process_id,
                    Request->process_name,
                    Request->monitor_flags
                );

                Irp->IoStatus.Information = 0;
            } else {
                Status = STATUS_INVALID_PARAMETER;
            }
            break;
        }

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}
```

---

## 关键功能实现

### 1. 调试器检测 (Ring 0)

```c
// 方法 1: 检查 KPROCESS.DebugPort
ULONG MTC_IsDebuggerAttached_Method1(PEPROCESS Process) {
    // KPROCESS.DebugPort 位于偏移量约 0x2F8 (Win10 x64)
    // 注：偏移量因 Windows 版本而异，需要动态获取

    ULONG DebugPort = *(PULONG)((PUCHAR)Process + 0x2F8);
    return (DebugPort != 0) ? 1 : 0;
}

// 方法 2: 检查 KdDebuggerEnabled
ULONG MTC_IsKernelDebuggerAttached(void) {
    extern ULONG KdDebuggerEnabled;
    return KdDebuggerEnabled ? 1 : 0;
}

// 完整实现
ULONG MTC_IsDebuggerAttached(void) {
    PEPROCESS CurrentProcess = PsGetCurrentProcess();

    // 检查用户态调试器
    if (MTC_IsDebuggerAttached_Method1(CurrentProcess)) {
        return 1;
    }

    // 检查内核调试器
    if (MTC_IsKernelDebuggerEnabled()) {
        return 1;
    }

    return 0;
}
```

### 2. 内存保护

```c
// Hook VirtualProtect (来自 NTDLL!NtProtectVirtualMemory)
// 检测非法权限变更

typedef NTSTATUS (*PFN_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

static PFN_NtProtectVirtualMemory g_OriginalNtProtectVirtualMemory = NULL;

NTSTATUS MTC_HookedNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    // 检查是否在尝试使代码段可写
    if ((NewProtect & PAGE_EXECUTE_WRITECOPY) || 
        (NewProtect & PAGE_READWRITE) ||
        (NewProtect & PAGE_EXECUTE_READWRITE)) {
        
        KdPrint(("[MTC] WARNING: Attempt to make code section writable!\n"));
        // 可选：拒绝请求或记录日志
    }

    // 调用原始函数
    return g_OriginalNtProtectVirtualMemory(
        ProcessHandle,
        BaseAddress,
        RegionSize,
        NewProtect,
        OldProtect
    );
}
```

### 3. SSDT Hook 检测

```c
// 检查 System Service Descriptor Table 是否被修改

ULONG MTC_DetectSyscallHooking(void) {
    // 在 Win10+ 上，直接枚举 ntoskrnl.exe 的导出函数
    // 比较当前地址与原始地址是否一致

    PIMAGE_EXPORT_DIRECTORY ExportDir = NULL;
    PULONG FunctionTable = NULL;
    PULONG NameTable = NULL;

    // 遍历 SSDT 检查常见系统调用是否被 Hook
    // 如: NtCreateProcess, NtWriteVirtualMemory, NtLoadDriver 等

    const char *critical_syscalls[] = {
        "NtCreateProcess",
        "NtWriteVirtualMemory",
        "NtLoadDriver",
        "NtSetInformationFile",
        NULL
    };

    for (int i = 0; critical_syscalls[i]; i++) {
        PVOID CurrentAddress = MmGetSystemRoutineAddress(
            (PUNICODE_STRING)critical_syscalls[i]
        );

        // 检查地址是否在 ntoskrnl.exe 范围内
        if (!MTC_IsAddressInKernel(CurrentAddress)) {
            KdPrint(("[MTC] SSDT Hook detected: %s\n", critical_syscalls[i]));
            return 1;
        }
    }

    return 0;
}
```

### 4. 进程通知回调

```c
VOID MTC_ProcessNotify(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    if (CreateInfo) {
        // 进程创建
        KdPrint(("[MTC] Process created: %lu (%wZ)\n", 
                 (ULONG)(ULONG_PTR)ProcessId,
                 CreateInfo->ImageFileName));

        // 检查是否尝试调试 Watchdog
        if (MTC_IsWatchdogProcess((ULONG)(ULONG_PTR)ProcessId)) {
            KdPrint(("[MTC] ALERT: Debugger attempting to attach to Watchdog!\n"));
            // 可选：终止该进程
            // ZwTerminateProcess(ProcessHandle, STATUS_CANCELLED);
        }
    } else {
        // 进程销毁
        KdPrint(("[MTC] Process terminated: %lu\n", (ULONG)(ULONG_PTR)ProcessId));
    }
}
```

---

## 编译与部署

### Visual Studio 项目配置

1. 创建 WDK Driver 项目
2. 配置 `MTC_FS_Driver.vcxproj`:

```xml
<PropertyGroup>
    <TargetVersion>Windows10</TargetVersion>
    <PlatformToolset>WindowsKernelModeDriver10.0</PlatformToolset>
    <Configuration>Release</Configuration>
</PropertyGroup>

<ItemDefinitionGroup>
    <ClCompile>
        <PreprocessorDefinitions>NDEBUG;%(PreprocessorDefinitions)</PreprocessorDefinitions>
    </ClCompile>
</ItemDefinitionGroup>
```

### 编译

```bash
# 使用 MSBuild
msbuild MTC_FS_Driver.sln /p:Configuration=Release /p:Platform=x64

# 输出文件
# .\x64\Release\MTC_FS_Driver.sys
# .\x64\Release\MTC_FS_Driver.pdb
```

### 代码签名（可选）

```bash
# 使用测试证书签名（开发环境）
signtool sign /f test_cert.pfx /p password MTC_FS_Driver.sys

# 或使用企业证书
signtool sign /sha1 "证书指纹" MTC_FS_Driver.sys
```

### 安装驱动

```bash
# 方法 1: 使用 sc.exe
sc create MTC_FS_Driver binPath= C:\Windows\System32\drivers\MTC_FS_Driver.sys
sc start MTC_FS_Driver

# 方法 2: 使用 DevCon
devcon install MTC_FS_Driver.inf

# 卸载
sc stop MTC_FS_Driver
sc delete MTC_FS_Driver
```

### 启用测试签名模式 (开发环境)

```bash
# 以管理员身份运行
bcdedit /set testsigning on
# 重启系统

# 禁用测试签名
bcdedit /set testsigning off
```

---

## 测试与调试

### 内核调试 (Kernel Debugging)

#### 设置 Hyper-V 虚拟机进行内核调试

1. **配置虚拟机**
   ```bash
   # 在宿主机上，编辑虚拟机配置以启用调试串口
   New-VMComPort -VMName "TestVM" -Number 1 -Path "\\.\pipe\dbg"
   ```

2. **在虚拟机内启用调试**
   ```bash
   bcdedit /debug on
   bcdedit /dbgsettings serial debugport:1 baudrate:115200
   ```

3. **连接调试器**
   ```bash
   # 宿主机上
   kd -k com:pipe,port=\\.\pipe\dbg,resets=0
   ```

### DbgView 日志

```bash
# 下载 Sysinternals DbgView
# https://docs.microsoft.com/en-us/sysinternals/downloads/debugview

# 运行驱动测试时，DbgView 会捕获所有 KdPrint 输出
DbgView.exe -c  # 清空日志
DbgView.exe     # 启动监听
```

### 驱动验证器 (Driver Verifier)

```bash
# 启用驱动验证
verifier /standard /driver MTC_FS_Driver.sys

# 重启系统应用设置
# 可以更严格地检测驱动中的 bugs

# 禁用驱动验证
verifier /reset
```

---

## 常见问题 & 故障排除

### 驱动加载失败

**症状:** `sc start MTC_FS_Driver` 返回错误

**排查:**
1. 检查驱动是否签名 (`signtool verify`)
2. 检查是否在测试签名模式下 (`bcdedit /enum | grep testsigning`)
3. 查看事件日志: `Event Viewer -> Windows Logs -> System`
4. 使用 `verifier /query` 检查驱动验证器报告

### 内核 Panic

**症状:** BSOD 或系统冻结

**排查:**
1. 连接内核调试器查看栈跟踪
2. 检查内存访问是否越界
3. 使用 KASAN 或 AddressSanitizer
4. 在驱动验证器下重现问题

### 性能问题

**症状:** 系统响应缓慢

**优化:**
1. 减少回调频率
2. 使用异步 I/O 而非同步阻塞
3. 优化 Hook 逻辑（最小化 Hot Path）
4. 使用定时器或 DPC 而非轮询

---

## 安全最佳实践

1. **入参验证**
   - 验证所有来自用户态的指针
   - 检查缓冲区大小，防止溢出

2. **权限控制**
   - 仅允许 SYSTEM 权限打开设备
   - 验证调用方身份

3. **反反调试**
   - 定期检查驱动自身完整性
   - 监控驱动被卸载的尝试

4. **错误处理**
   - 所有系统调用都检查返回值
   - 合理处理异常情况，避免 Panic

---

## 参考资源

- [Windows Driver Kit (WDK) 官方文档](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
- [内核编程指南](https://github.com/reactos/reactos)
- [Sysinternals 工具套件](https://docs.microsoft.com/en-us/sysinternals/)
- [Windows 内核安全](https://www.malwarebytes.com/resources/files/2017/12/Windows_Kernel_Security.pdf)

---

## 许可证

MIT License - 本驱动框架可自由修改和使用
