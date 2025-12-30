# Watchdog 快速参考 (Quick Reference)

## 编译

```bash
gcc -o Watchdog.exe Watchdog.c -lkernel32 -lpsapi -ladvapi32
```

## 命令行启动

```bash
# 基础监护
Watchdog.exe --target-pid <PID>

# 启用篡改检测
Watchdog.exe --target-pid <PID> --enable-tamper-detection

# 启用调试输出
Watchdog.exe --target-pid <PID> --debug

# 完整参数
Watchdog.exe --target-pid <PID> --check-interval 1000 --enable-tamper-detection --debug
```

## 代码集成 (3 步)

### 1. 包含头文件
```c
#include "Watchdog.h"
```

### 2. 初始化与启动
```c
WatchdogConfig config = {0};
config.target_process_id = target_pid;
config.enable_tamper_detection = 1;
config.enable_debug_mode = 1;

Watchdog_Init(&config);
Watchdog_Start();
```

### 3. 清理
```c
Watchdog_Stop();
```

## 主要 API

| 函数 | 功能 |
|------|------|
| `Watchdog_Init()` | 初始化配置 |
| `Watchdog_Start()` | 启动监护线程 |
| `Watchdog_Stop()` | 停止监护 |
| `Watchdog_IsTargetProcessAlive()` | 检查进程活性 |
| `Watchdog_DetectTamper()` | 执行篡改检测 |
| `Watchdog_GetProcessCodeHash()` | 获取代码校验和 |
| `Watchdog_TriggerKernelHalt()` | 触发系统冻结 |

## 配置项

```c
typedef struct {
    DWORD target_process_id;           // ⚠️ 必需
    DWORD check_interval_ms;           // 默认: 1000
    int enable_tamper_detection;       // 默认: 0
    int enable_debug_mode;             // 默认: 0
    int kernel_force_halt_enabled;     // 默认: 0
} WatchdogConfig;
```

## 返回值

| 值 | 含义 |
|----|------|
| 0 | 成功 |
| -1 | 初始化失败 |
| -2 | 驱动未找到 |
| -3 | 驱动通信错误 |
| -4 | 进程已终止 |
| -5 | 检测到篡改 |
| -6 | 冻结失败 |

## 篡改检测结果

```c
typedef struct {
    int is_debugger_attached;      // 调试器已附加
    int is_process_suspended;      // 进程被挂起
    int memory_pages_modified;     // 修改的内存页数
    int code_section_altered;      // 代码段被篡改
    char tamper_reason[256];       // 原因说明
} TamperDetectionResult;
```

## 常见模式

### 独立进程监护
```bash
# 启动主程序
main.exe &

# 获取 PID，启动 Watchdog
Watchdog.exe --target-pid %MAIN_PID% --enable-tamper-detection
```

### 主程序内部集成
```c
// 创建被监护的子进程
CreateProcessA("target.exe", ...);

// 初始化 Watchdog 监护它
Watchdog_Init(&config);
Watchdog_Start();

// 继续业务逻辑
// ...
```

### 主动检测（无自动监护）
```c
Watchdog_Init(&config);
// 不调用 Watchdog_Start()

while (1) {
    TamperDetectionResult result = {0};
    Watchdog_DetectTamper(&result);
    
    if (result.is_debugger_attached) {
        // 处理调试器附加
    }
    Sleep(1000);
}
```

## 检查间隔建议

| 场景 | 间隔 | CPU 占用 |
|------|------|---------|
| 实时防护 | 100-500ms | 1-2% |
| 推荐 | 1000-2000ms | <1% |
| 低消耗 | 5000-10000ms | <0.1% |

## 内核驱动集成

```c
// 启用内核级防护
config.kernel_force_halt_enabled = 1;
strcpy(config.kernel_driver_path, "MTC_FS_Driver.sys");

// 驱动不可用时自动降级到用户态方案
if (Watchdog_Init(&config) == WATCHDOG_DRIVER_NOT_FOUND) {
    printf("Using fallback user-mode protection\n");
}
```

## 故障排除

| 问题 | 解决方案 |
|------|---------|
| 无法打开目标进程 | 检查 PID 是否正确，进程是否仍在运行 |
| 驱动不可用 | 部署 MTC_FS_Driver.sys，或禁用 kernel_force_halt_enabled |
| 检测到误报 | 调整 check_interval_ms，或在开发环境禁用篡改检测 |
| 虚拟机中不工作 | 使用完整虚拟化而非 Hyper-V，或禁用虚拟机检测 |

## 性能指标

- **内存占用**: 2-5 MB (用户态)
- **CPU 占用**: <1% @ 1000ms 检查间隔
- **初始化时间**: <100ms
- **检测延迟**: ~50ms (用户态)

## 文件清单

| 文件 | 说明 |
|------|------|
| `Watchdog.h` | 公开接口 |
| `Watchdog.c` | 用户态实现 |
| `MTC_FS_Driver.h` | 内核驱动规范 |
| `Watchdog_Example.c` | 使用示例 |

## 相关链接

- [完整使用指南](./Watchdog_Usage_Guide.md)
- [内核驱动开发](./Kernel_Driver_Development.md)
- [MTC 项目主页](../README.md)
