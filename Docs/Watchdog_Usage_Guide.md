# MTC Watchdog 使用指南

## 概述

**Watchdog** 是 MTC 系统中的核心安全守护组件，负责监控主程序的完整性与运行状态。它通过进程监控、篡改检测、调试器检测等多层防护机制，确保主程序不被非法修改、调试或终止。

Watchdog 分为两部分：
- **用户态 (Ring 3)**: 独立运行的监护程序，提供进程监控和初级篡改检测
- **内核态 (Ring 0)**: 可选的内核驱动，提供更强大的防护与强制系统冻结功能

---

## 架构概述

```
┌─────────────────────────────────────────────────────┐
│  Main Program (主程序)                              │
│  - 执行业务逻辑                                      │
│  - 定期检查 Watchdog 状态                            │
└─────────────────────────────────────────────────────┘
                        ↕ (监控)
┌─────────────────────────────────────────────────────┐
│  Watchdog (用户态)                                   │
│  - 检查进程活性                                      │
│  - 调试器检测 (Ring 3)                               │
│  - 代码段完整性校验                                  │
│  - 与内核驱动通信                                    │
└─────────────────────────────────────────────────────┘
                        ↕ (DeviceIoControl)
┌─────────────────────────────────────────────────────┐
│  MTC Kernel Driver (可选)                            │
│  - 进程事件监控                                      │
│  - 调试器检测 (Ring 0)                               │
│  - 内存保护与篡改检测                                │
│  - 系统调用 Hook 检测                                │
│  - 强制 BSOD                                         │
└─────────────────────────────────────────────────────┘
```

---

## 快速开始

### 1. 基础使用 (无内核驱动)

如果暂时没有内核驱动，可以使用用户态 Watchdog，功能相对受限但可以立即运行。

#### 步骤 1: 编译 Watchdog

```bash
cd Sample\ClientApps\Watchdog
gcc -o Watchdog.exe Watchdog.c -lkernel32 -lpsapi -ladvapi32 -lws2_32
```

#### 步骤 2: 启动主程序与 Watchdog

主程序启动后，单独启动 Watchdog 进程进行监护：

```bash
# 终端 1: 启动主程序
main.exe

# 终端 2: 启动 Watchdog（假设主程序 PID = 1234）
Watchdog.exe --target-pid 1234 --check-interval 1000 --enable-tamper-detection --debug
```

或通过命令行参数传递 PID：

```bash
Watchdog.exe --target-pid %MAIN_PID% --enable-tamper-detection
```

#### 步骤 3: 观察监控输出

Watchdog 会定期输出监控状态：

```
[Watchdog 2025-12-30 14:30:45] Watchdog initialized for PID 1234
[Watchdog 2025-12-30 14:30:45] Watchdog monitoring started
[Watchdog 2025-12-30 14:30:45] Sending request to 127.0.0.1:3502/api/sync
[Watchdog 2025-12-30 14:30:46] Connected to 127.0.0.1:3502
[Watchdog 2025-12-30 14:30:46] Request sent
[Watchdog 2025-12-30 14:30:47] Response received: {"status":"ok"}
```

---

### 2. 在代码中集成 Watchdog

如果要在主程序中主动使用 Watchdog API：

#### 步骤 1: 包含头文件

```c
#include "Watchdog.h"
```

#### 步骤 2: 配置与初始化

```c
#include <stdio.h>
#include <windows.h>
#include "Watchdog.h"

int main(int argc, char **argv) {
    // 创建要被监护的子进程
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    if (!CreateProcessA("target_program.exe", NULL, NULL, NULL, 
                        FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("Failed to create target process\n");
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
    config.kernel_force_halt_enabled = 0;      // 暂不启用内核冻结
    
    // 初始化
    if (Watchdog_Init(&config) != WATCHDOG_OK) {
        printf("Watchdog init failed\n");
        return 1;
    }
    
    // 启动监护
    if (Watchdog_Start() != WATCHDOG_OK) {
        printf("Watchdog start failed\n");
        return 1;
    }
    
    printf("Watchdog started, monitoring PID %lu\n", target_pid);
    
    // 主程序继续运行，Watchdog 在后台监护
    // ...
    
    // 正常退出时停止 Watchdog
    Watchdog_Stop();
    return 0;
}
```

#### 步骤 3: 编译并运行

```bash
gcc -o main.exe main.c Watchdog.c -lkernel32 -lpsapi -ladvapi32
main.exe
```

---

## 高级用法

### 主动进行篡改检测

不启动自动监护线程，而是在适当时机主动检查：

```c
#include "Watchdog.h"

int main(void) {
    // 配置 Watchdog
    WatchdogConfig config = {0};
    config.target_process_id = GetCurrentProcessId();
    config.enable_tamper_detection = 1;
    config.enable_debug_mode = 1;
    
    if (Watchdog_Init(&config) != WATCHDOG_OK) {
        return 1;
    }
    
    // 不调用 Watchdog_Start()，手动执行检测
    
    for (int i = 0; i < 10; i++) {
        printf("\n=== Check %d ===\n", i + 1);
        
        // 执行篡改检测
        TamperDetectionResult result = {0};
        if (Watchdog_DetectTamper(&result) == WATCHDOG_OK) {
            printf("Debugger attached: %s\n", 
                   result.is_debugger_attached ? "YES [ALERT!]" : "NO");
            printf("Process suspended: %s\n", 
                   result.is_process_suspended ? "YES [ALERT!]" : "NO");
            
            if (result.tamper_reason[0]) {
                printf("Tamper reason: %s\n", result.tamper_reason);
            }
        }
        
        // 获取代码段校验和
        unsigned char code_hash[32];
        if (Watchdog_GetProcessCodeHash(code_hash, sizeof(code_hash)) == WATCHDOG_OK) {
            printf("Code checksum: 0x%08X\n", *(unsigned int *)code_hash);
        }
        
        Sleep(5000);
    }
    
    Watchdog_Stop();
    return 0;
}
```

### 与 NetDeliver 配合使用

Watchdog 可以通过 NetDeliver 定期上报监控状态到服务器：

```c
#include "Watchdog.h"
#include "NetDeliver.h"

void watchdog_heartbeat_thread(void *arg) {
    while (1) {
        Sleep(60000);  // 每 60 秒上报一次
        
        TamperDetectionResult result = {0};
        Watchdog_DetectTamper(&result);
        
        // 构造上报 JSON
        char json[512];
        snprintf(json, sizeof(json),
                 "{\"heartbeat\":true,\"tamper_detected\":%d,\"debug_attached\":%d}",
                 (result.is_debugger_attached || result.is_process_suspended) ? 1 : 0,
                 result.is_debugger_attached ? 1 : 0);
        
        // 发送到服务器
        NetResponse *resp = NetDeliver_SendRequest("/api/heartbeat", json);
        if (resp) {
            printf("Heartbeat sent, response: %d\n", resp->status_code);
            NetDeliver_FreeResponse(resp);
        }
    }
}
```

---

## 内核驱动集成 (可选)

### 驱动需求

如果要启用强制系统冻结和 Ring 0 级调试器检测，需要开发内核驱动 `MTC_FS_Driver.sys`。

#### 驱动需要实现的功能

1. **进程事件监控**
   - 注册进程创建/销毁回调
   - 检测目标进程异常退出

2. **调试器检测 (Ring 0)**
   - 检查 KPROCESS.DebugPort
   - 监控 KdInitSystem 的调用

3. **内存保护与篡改检测**
   - Hook VirtualProtect/VirtualProtectEx
   - 检测代码段权限变更
   - 检测恶意 DLL 注入

4. **系统调用 Hook 检测**
   - 检查 SSDT (System Service Descriptor Table) 被修改
   - 检测内核 Hook 框架

5. **强制 BSOD**
   - 实现 `IOCTL_WATCHDOG_HALT` 处理
   - 调用 `KeBugCheckEx(0xDEADBEEF, ...)`

### 驱动框架

详见 [MTC_FS_Driver.h](../Sample/ClientApps/Watchdog/MTC_FS_Driver.h) 中的完整框架。

### 启用驱动

驱动部署后，在配置中启用：

```c
WatchdogConfig config = {0};
// ... 其他配置 ...
config.kernel_force_halt_enabled = 1;
strcpy(config.kernel_driver_path, "C:\\Windows\\System32\\drivers\\MTC_FS_Driver.sys");

if (Watchdog_Init(&config) != WATCHDOG_OK) {
    printf("Failed to initialize kernel driver\n");
    // 可选：降级到用户态方案
}
```

---

## 配置参数详解

### WatchdogConfig 结构体

```c
typedef struct {
    DWORD target_process_id;          // 目标进程 ID（必需）
    char target_process_name[256];    // 进程名称，用于日志辅助识别
    DWORD check_interval_ms;          // 检查间隔（毫秒），默认 1000
    int enable_tamper_detection;      // 是否启用篡改检测 (0/1)
    int enable_debug_mode;            // 是否启用调试输出 (0/1)
    int kernel_force_halt_enabled;    // 是否启用内核级强制冻结 (0/1)
    char kernel_driver_path[512];     // 内核驱动路径
} WatchdogConfig;
```

### 参数说明

| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `target_process_id` | DWORD | 是 | 要监护的进程 ID |
| `target_process_name` | char[256] | 否 | 进程名称，仅用于日志 |
| `check_interval_ms` | DWORD | 否 | 检查间隔，默认 1000ms |
| `enable_tamper_detection` | int | 否 | 是否启用篡改检测，默认 0 |
| `enable_debug_mode` | int | 否 | 是否输出调试日志，默认 0 |
| `kernel_force_halt_enabled` | int | 否 | 是否启用内核冻结，默认 0 |
| `kernel_driver_path` | char[512] | 否 | 驱动文件路径 |

---

## API 参考

### 初始化 & 控制

```c
// 初始化 Watchdog
WatchdogStatus Watchdog_Init(WatchdogConfig *config);

// 启动监护线程
WatchdogStatus Watchdog_Start(void);

// 停止监护
WatchdogStatus Watchdog_Stop(void);

// 检查目标进程是否活跃 (1=活跃, 0=已终止, <0=错误)
int Watchdog_IsTargetProcessAlive(void);
```

### 检测 & 分析

```c
// 执行篡改检测
WatchdogStatus Watchdog_DetectTamper(TamperDetectionResult *result);

// 获取进程代码段校验和
WatchdogStatus Watchdog_GetProcessCodeHash(unsigned char *out_hash, int hash_len);
```

### 强制冻结

```c
// 触发系统冻结 (BSOD)
WatchdogStatus Watchdog_TriggerKernelHalt(const char *reason);
```

### 工具函数

```c
// 输出调试日志（仅在 enable_debug_mode=1 时输出）
void Watchdog_DebugLog(const char *fmt, ...);
```

---

## 错误处理

### 返回状态码

```c
typedef enum {
    WATCHDOG_OK = 0,                      // 成功
    WATCHDOG_INIT_FAILED = -1,            // 初始化失败
    WATCHDOG_DRIVER_NOT_FOUND = -2,       // 内核驱动未找到
    WATCHDOG_DRIVER_COMM_ERROR = -3,      // 驱动通信错误
    WATCHDOG_PROCESS_TERMINATED = -4,     // 目标进程已终止
    WATCHDOG_TAMPER_DETECTED = -5,        // 检测到篡改
    WATCHDOG_KERNEL_HALT_FAILED = -6      // 内核冻结失败
} WatchdogStatus;
```

### 常见错误与解决

| 错误 | 原因 | 解决方案 |
|------|------|---------|
| WATCHDOG_INIT_FAILED | 配置无效或内存不足 | 检查 target_process_id，确保进程存在 |
| WATCHDOG_DRIVER_NOT_FOUND | 内核驱动未部署 | 关闭 kernel_force_halt_enabled，或部署驱动 |
| WATCHDOG_PROCESS_TERMINATED | 目标进程已退出 | 这是正常的终止信号，检查进程是否正常停止 |
| WATCHDOG_TAMPER_DETECTED | 检测到篡改行为 | 检查调试器/篡改工具，系统将自动冻结 |

---

## 篡改检测详解

### TamperDetectionResult 结构体

```c
typedef struct {
    int is_debugger_attached;         // 是否有调试器附加 (WinDbg/OllyDbg 等)
    int is_process_suspended;         // 进程是否被 SuspendThread 挂起
    int memory_pages_modified;        // 内存页被修改数量
    int code_section_altered;         // 代码段是否被篡改
    char tamper_reason[256];          // 篡改原因描述
} TamperDetectionResult;
```

### 检测项

**用户态可检测：**
- ✅ 调试器附加 (使用 CheckRemoteDebuggerPresent)
- ✅ 进程线程状态
- ✅ 代码段校验和

**内核态可检测（需驱动）：**
- ✅ 内核调试器状态 (KdInitSystem)
- ✅ SSDT Hook 检测
- ✅ 内存页保护属性变更
- ✅ DLL 注入检测
- ✅ 系统调用 Hook 框架

---

## 性能考虑

### 检查间隔建议

| 场景 | 建议间隔 | 说明 |
|------|----------|------|
| 实时性要求高 | 100-500ms | CPU 占用约 1-2% |
| 平衡方案（推荐） | 1000-2000ms | CPU 占用 <1% |
| 低消耗方案 | 5000-10000ms | CPU 占用 <0.1% |

### 内存占用

- 用户态 Watchdog: ~2-5 MB
- 内核驱动: ~5-10 MB (取决于 Hook 数量)

### 降级机制

当内核驱动不可用时：

1. 自动降级到用户态检测
2. 检测到篡改时使用 `shutdown /s /f /t 1` 强制关闭系统
3. 功能仍完整，但冻结方式从 BSOD 变为系统关闭

---

## 测试与验证

### 单元测试

```bash
# 编译测试程序
gcc -o test_watchdog.exe test_watchdog.c Watchdog.c -lkernel32 -lpsapi -ladvapi32

# 运行测试
test_watchdog.exe
```

### 功能验证

1. **进程监控**：手动终止目标进程，验证 Watchdog 检测并响应
2. **调试器检测**：用 OllyDbg/WinDbg 附加目标进程，验证检测与冻结
3. **代码完整性**：通过十六进制编辑器修改进程内存，验证校验和变化
4. **内核驱动**：安装驱动后验证 BSOD 触发

### 压力测试

```c
// 高频检测压力测试
for (int i = 0; i < 10000; i++) {
    TamperDetectionResult result = {0};
    Watchdog_DetectTamper(&result);
}
```

---

## 常见问题 (FAQ)

### Q: Watchdog 可以在主程序内部运行吗？
A: 可以，但建议独立进程运行。在主程序内部运行可能被篡改工具同时攻击。独立进程提供更好的隔离性。

### Q: 如何防止 Watchdog 本身被攻击？
A: 
1. 内核驱动可以监护 Watchdog 进程本身
2. 使用代码签名与完整性校验
3. 将 Watchdog 进程设置为系统进程（需 SYSTEM 权限）

### Q: 是否支持 64 位系统？
A: 是的。Watchdog 既支持 32 位也支持 64 位 Windows。内核驱动需要分别编译。

### Q: 调试器检测会影响合法调试吗？
A: 是的，这是设计目的。在开发环境中建议禁用 `enable_tamper_detection`。

### Q: 如何在虚拟机中测试？
A: 虚拟机检测需要额外模块。可以使用 Hyper-V/VMware 的完整模式运行，或禁用虚拟机检测进行开发测试。

### Q: Watchdog 可以在远程桌面中运行吗？
A: 可以，但某些 Ring 0 检测可能不可用。用户态检测完全支持。

---

## 许可证

MIT License - 详见项目根目录的 LICENSE 文件

---

## 相关文档

- [MTC 项目 README](../README.md)
- [NetDeliver 使用指南](./NetDeliver_Usage_Guide.md)
- [Kernel Driver 开发指南](./Kernel_Driver_Development.md)
- [安全威胁模型分析](./Threat_Model.md)
