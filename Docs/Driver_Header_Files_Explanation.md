# MTC Watchdog 驱动头文件说明

## 文件清单

### 1. **MTC_FS_Driver.h** (内核驱动版本)

**用途**: 开发 Windows 内核驱动时使用

**特点**:
- 依赖 WDK (Windows Driver Kit) 头文件
- 包含 `<ntdef.h>`, `<ntifs.h>`, `<ntstatus.h>`
- 定义完整的驱动 API 和数据结构
- 包含内核驱动实现框架示例

**使用场景**:
- 在 Visual Studio + WDK 环境下开发驱动
- 驱动源码中包含此文件
- Ring 0 内核代码

**编译环境**:
```bash
# Visual Studio + Windows Driver Kit
# 不支持 MinGW / GCC
```

---

### 2. **MTC_FS_Driver_UserMode.h** (用户态版本)

**用途**: 用户态应用程序调用驱动时使用

**特点**:
- 仅依赖标准 Windows SDK (windows.h)
- **不依赖 WDK**
- 定义与驱动通信所需的结构体和 IOCTL 常量
- 用户态程序都通过此头文件与驱动通信

**使用场景**:
- 用户态监护程序 (Watchdog.c)
- 应用程序与驱动交互
- Ring 3 用户态代码

**编译环境**:
```bash
# MinGW / GCC
# Visual Studio (任何配置)
# 任何标准 C 编译器
```

---

### 3. **Watchdog.h** (监护程序公开接口)

**用途**: Watchdog 用户态程序的公开 API

**包含**: `MTC_FS_Driver_UserMode.h`（不是 WDK 驱动版本）

**编译环境**: MinGW / GCC / MSVC

---

## 对应关系

```
MTC_FS_Driver.h (内核驱动开发)
    ↓
    ├─→ 内核驱动源码 (DriverEntry, MTC_DeviceControl 等)
    │
    └─→ 结构体定义 (WATCHDOG_HALT_REQUEST 等)
        ↓
        转移到用户态版本
        ↓
MTC_FS_Driver_UserMode.h (用户态应用)
    ↓
    └─→ Watchdog.h, Watchdog.c (用户态程序)
    └─→ 其他应用程序 (需要调用驱动)
```

---

## 如何编译

### 编译 Watchdog 用户态程序

```bash
# 这样可以正常编译，不会报 ntifs.h 错误
gcc -o Watchdog.exe Watchdog.c -lkernel32 -lpsapi -ladvapi32 -lws2_32
```

**关键点**: 使用 `MTC_FS_Driver_UserMode.h`，不使用 `MTC_FS_Driver.h`

### 开发内核驱动

```bash
# 在 Visual Studio + WDK 环境中
# 1. 创建 WDK Driver 项目
# 2. 包含 MTC_FS_Driver.h
# 3. 实现 DriverEntry, MTC_DeviceControl 等函数
# 4. 使用 MSBuild 编译生成 .sys 文件

msbuild MTC_FS_Driver.sln /p:Configuration=Release /p:Platform=x64
```

---

## 常见问题

### Q1: 为什么我编译 Watchdog 时报 "ntifs.h not found"?

**A**: 之前 Watchdog.h 错误地包含了驱动版本的 `MTC_FS_Driver.h`。已修复：
- ✅ Watchdog.h 现在包含 `MTC_FS_Driver_UserMode.h`
- ✅ `MTC_FS_Driver_UserMode.h` 只依赖 windows.h
- ✅ MinGW/GCC 可以正常编译

### Q2: ntifs.h 是什么？

**A**: `ntifs.h` 是 Windows Driver Kit 中的内核头文件，定义 NT 文件系统接口。仅在开发内核驱动时使用，用户态程序不需要。

### Q3: 我能否直接在 MinGW 中编译驱动?

**A**: 不能。Windows 内核驱动**必须**使用 WDK + Visual Studio 编译。这涉及：
- 特殊的链接脚本
- 代码签名要求
- 驱动校验 (Driver Verifier)
- 其他内核级工具链

MinGW 是用户态工具链，无法编译内核驱动。

### Q4: 两个头文件定义完全相同吗?

**A**: 基本相同，但有细微差别：

| 项目 | MTC_FS_Driver.h | MTC_FS_Driver_UserMode.h |
|------|-----------------|--------------------------|
| 依赖项 | WDK 头文件 | 仅 windows.h |
| 类型定义 | ULONG, UCHAR, ULONGLONG | ULONG, unsigned char, unsigned long long |
| 完整性 | 包含完整驱动框架 | 仅包含通信接口 |
| 使用场景 | 驱动开发 | 应用开发 |

### Q5: 我可以同时包含两个头文件吗?

**A**: 在不同的项目中可以：
- **驱动项目**: 包含 `MTC_FS_Driver.h`
- **应用项目**: 包含 `MTC_FS_Driver_UserMode.h`

不要在同一个项目中同时包含两者。

### Q6: 如果驱动更新了结构体，我需要做什么?

**A**: 
1. 更新 `MTC_FS_Driver.h` (驱动实现)
2. **同步更新** `MTC_FS_Driver_UserMode.h` (用户态接口)
3. 两个文件中的结构体定义必须完全对齐，否则会导致通信错误

---

## 最佳实践

### ✅ 正确做法

```c
// Watchdog.c (用户态)
#include "Watchdog.h"  // 包含 MTC_FS_Driver_UserMode.h

// 驱动代码 (内核)
#include "MTC_FS_Driver.h"  // 包含 WDK 头文件
```

### ❌ 错误做法

```c
// 用户态程序中包含驱动头文件
#include "MTC_FS_Driver.h"  // ❌ 报 ntifs.h not found 错误

// 驱动中包含用户态头文件
#include "MTC_FS_Driver_UserMode.h"  // ❌ 定义不完整，缺少内核 API
```

---

## 文件结构总结

```
Sample/ClientApps/Watchdog/
├── MTC_FS_Driver.h                  ← 内核驱动版本 (WDK)
├── MTC_FS_Driver_UserMode.h         ← 用户态版本 (MinGW/GCC 可用)
├── Watchdog.h                       ← 公开接口 (包含 UserMode 版本)
├── Watchdog.c                       ← 用户态实现
├── Watchdog_Example.c               ← 使用示例
└── Watchdog_Quick_Reference.md      ← 快速参考
```

---

## 编译命令参考

### 编译用户态 Watchdog

```bash
cd Sample\ClientApps\Watchdog

# 使用 MinGW GCC
gcc -o Watchdog.exe Watchdog.c MTC_FS_Driver_UserMode.h \
    -lkernel32 -lpsapi -ladvapi32 -lws2_32

# 或使用 Visual Studio CL
cl /O2 Watchdog.c /link kernel32.lib psapi.lib advapi32.lib ws2_32.lib
```

### 编译内核驱动

```bash
# 在 Visual Studio + WDK 中
# File -> New -> Project -> Windows Driver Kit -> Kernel Mode Driver

# 使用 MSBuild
msbuild MTC_FS_Driver_Kernel.sln /p:Configuration=Release /p:Platform=x64
```

---

## 相关文档

- [Watchdog 使用指南](./Watchdog_Usage_Guide.md)
- [内核驱动开发指南](./Kernel_Driver_Development.md)
- [快速参考](./Watchdog_Quick_Reference.md)
