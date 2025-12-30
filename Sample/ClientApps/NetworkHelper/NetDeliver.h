#ifndef NETDELIVER_H
#define NETDELIVER_H

typedef struct {
    int IsDebug;
    char Dist_Server[256];
    char IP[64];
    char Port[32];
    char AppPath[512];
} NetConfig;

typedef struct {
    int status_code;        // HTTP status code
    char *data;             // Response body (JSON)
    int data_len;
} NetResponse;

// 初始化网络配置，应在程序启动时调用一次
void NetDeliver_Init(int argc, char **argv);

// 获取当前网络配置
NetConfig* NetDeliver_GetConfig(void);

// 调试打印网络请求（当 IsDebug=1 时）
void NetDeliver_DebugPrint(const char *fmt, ...);

// 发送网络请求：接收 JSON 数据，向 Dist-Server 发送，返回 JSON 响应
// 参数:
//   endpoint  - 请求路径 (例如 "/api/sync")
//   json_data - 请求的 JSON 数据（字符串）
// 返回:
//   NetResponse* - 包含状态码和响应 JSON 数据的结构
//   需要用 NetDeliver_FreeResponse() 释放内存
NetResponse* NetDeliver_SendRequest(const char *endpoint, const char *json_data);

// 释放 NetResponse 内存
void NetDeliver_FreeResponse(NetResponse *resp);

#endif // NETDELIVER_H
