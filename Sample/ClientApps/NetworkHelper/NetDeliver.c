#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

/* ===== Network Request/Response Structure ===== */

typedef struct {
    int status_code;        // HTTP status code
    char *data;             // Response body (JSON)
    int data_len;
} NetResponse;

/* ===== Debug Configuration & INI Parsing ===== */

typedef struct {
    int IsDebug;
    char Dist_Server[256];
    char IP[64];
    char Port[32];
    char AppPath[512];
} NetConfig;

static NetConfig g_config = {0};
static int g_config_initialized = 0;

// 辅助函数：去掉首尾空格及两端的双引号
static char *trim_and_unquote(char *s) {
    char *p = s;
    // 去掉开头的空格
    while (*p && isspace((unsigned char)*p)) p++;
    
    // 去掉结尾的空格
    char *end = p + strlen(p) - 1;
    while (end > p && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    // 如果首尾有双引号，去掉它们
    if (*p == '"' && *end == '"' && end > p) {
        *end = '\0';
        p++;
    }
    return p;
}

static int strieq(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == *b;
}

// 初始化网络配置，应在程序启动时调用一次
void NetDeliver_Init(int argc, char **argv) {
    if (g_config_initialized) return;
    
    int IsDebug = 0;

    // 1. 检查环境变量
    char *env = getenv("IsDebug");
    if (env && (strieq(env, "1") || strieq(env, "true"))) IsDebug = 1;

    // 2. 检查命令行参数
    for (int i = 1; i < argc; ++i) {
        if (strieq(argv[i], "--debug") || strieq(argv[i], "-d") || strieq(argv[i], "debug")) {
            IsDebug = 1; break;
        }
        if (strncmp(argv[i], "IsDebug=", 8) == 0) {
            char *v = argv[i] + 8;
            if (strieq(v, "1") || strieq(v, "true")) { IsDebug = 1; break; }
        }
    }

    // 默认值
    g_config.IsDebug = IsDebug;
    strcpy(g_config.Dist_Server, "am-dist.AkiACG.com");
    strcpy(g_config.IP, "172.16.8.48");
    strcpy(g_config.Port, "3502");
    strcpy(g_config.AppPath, "..\\main.exe");

    // 3. 解析 INI
    if (IsDebug) {
        FILE *f = fopen("AkiTools.ini", "r");
        if (f) {
            char line[1024];
            int inDebugSection = 0;
            while (fgets(line, sizeof(line), f)) {
                char *ln = trim_and_unquote(line);

                // 过滤空行和多种注释 (;, #, //)
                if (ln[0] == '\0' || ln[0] == ';' || ln[0] == '#' || (ln[0] == '/' && ln[1] == '/')) 
                    continue;

                // 识别 Section
                if (ln[0] == '[') {
                    if (strieq(ln, "[Debug]")) inDebugSection = 1;
                    else inDebugSection = 0;
                    continue;
                }

                // 在 [Debug] 块内解析
                if (inDebugSection) {
                    char *eq = strchr(ln, '=');
                    if (!eq) continue;

                    *eq = '\0';
                    char *key = trim_and_unquote(ln);
                    char *val = trim_and_unquote(eq + 1);

                    if (strieq(key, "Dist-Server") || strieq(key, "Dist_Server")) {
                        strncpy(g_config.Dist_Server, val, sizeof(g_config.Dist_Server)-1);
                    } else if (strieq(key, "IP")) {
                        strncpy(g_config.IP, val, sizeof(g_config.IP)-1);
                    } else if (strieq(key, "Port")) {
                        strncpy(g_config.Port, val, sizeof(g_config.Port)-1);
                    } else if (strieq(key, "AppPath")) {
                        strncpy(g_config.AppPath, val, sizeof(g_config.AppPath)-1);
                    }
                }
            }
            fclose(f);
        }
    }

    g_config_initialized = 1;
    
    // 输出结果
    if (g_config.IsDebug) {
        printf("--- NetDeliver Configuration ---\n");
        printf("IsDebug     : %d\n", g_config.IsDebug);
        printf("Dist-Server : %s\n", g_config.Dist_Server);
        printf("IP          : %s\n", g_config.IP);
        printf("Port        : %s\n", g_config.Port);
        printf("AppPath     : %s\n", g_config.AppPath);
    }
}

// 获取当前网络配置
NetConfig* NetDeliver_GetConfig(void) {
    if (!g_config_initialized) {
        fprintf(stderr, "Warning: NetConfig not initialized. Call NetDeliver_Init() first.\n");
    }
    return &g_config;
}

// 调试打印网络请求（当 IsDebug=1 时）
void NetDeliver_DebugPrint(const char *fmt, ...) {
    if (!g_config.IsDebug) return;
    
    va_list args;
    va_start(args, fmt);
    printf("[NetDeliver DEBUG] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

/* ===== Network Request Functions ===== */

// 简单的 Base64 编码（用于请求体编码）
static void base64_encode(const char *src, int src_len, char *dst, int dst_size) {
    const char *base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int dst_idx = 0;
    
    for (int i = 0; i < src_len && dst_idx < dst_size - 4; i += 3) {
        unsigned char b1 = (unsigned char)src[i];
        unsigned char b2 = (i + 1 < src_len) ? (unsigned char)src[i + 1] : 0;
        unsigned char b3 = (i + 2 < src_len) ? (unsigned char)src[i + 2] : 0;
        
        int n = (b1 << 16) | (b2 << 8) | b3;
        int b_pad = 3 - (src_len - i); // 补齐字节数
        
        dst[dst_idx++] = base64_table[(n >> 18) & 0x3F];
        dst[dst_idx++] = base64_table[(n >> 12) & 0x3F];
        dst[dst_idx++] = (b_pad > 1) ? '=' : base64_table[(n >> 6) & 0x3F];
        dst[dst_idx++] = (b_pad > 0) ? '=' : base64_table[n & 0x3F];
    }
    
    if (dst_idx < dst_size) dst[dst_idx] = '\0';
}

// 发送 HTTP 请求到 Dist-Server
// 参数: endpoint - 请求路径，json_data - JSON 请求体
// 返回: NetResponse 结构，包含状态码和响应 JSON
NetResponse* NetDeliver_SendRequest(const char *endpoint, const char *json_data) {
    NetResponse *resp = (NetResponse *)malloc(sizeof(NetResponse));
    if (!resp) return NULL;
    
    resp->status_code = 0;
    resp->data = NULL;
    resp->data_len = 0;
    
    if (!g_config_initialized) {
        fprintf(stderr, "Error: NetDeliver not initialized. Call NetDeliver_Init() first.\n");
        resp->status_code = -1;
        return resp;
    }
    
    // 对请求数据进行 Base64 编码
    int json_len = strlen(json_data);
    char *encoded_data = (char *)malloc(json_len * 2 + 10);
    if (!encoded_data) {
        free(resp);
        return NULL;
    }
    base64_encode(json_data, json_len, encoded_data, json_len * 2 + 10);
    
    NetDeliver_DebugPrint("Sending request to %s:%s%s", g_config.IP, g_config.Port, endpoint);
    NetDeliver_DebugPrint("Encoded payload: %s", encoded_data);
    
    // 创建 TCP 连接到 Dist-Server
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        NetDeliver_DebugPrint("WSAStartup failed");
        resp->status_code = -2;
        free(encoded_data);
        return resp;
    }
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        NetDeliver_DebugPrint("Socket creation failed");
        resp->status_code = -3;
        WSACleanup();
        free(encoded_data);
        return resp;
    }
    
    // 连接到 Dist-Server
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(atoi(g_config.Port));
    server_addr.sin_addr.s_addr = inet_addr(g_config.IP);
    
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        NetDeliver_DebugPrint("Connection failed to %s:%s", g_config.IP, g_config.Port);
        resp->status_code = -4;
        closesocket(sock);
        WSACleanup();
        free(encoded_data);
        return resp;
    }
    
    NetDeliver_DebugPrint("Connected to %s:%s", g_config.IP, g_config.Port);
    
    // 构造 HTTP 请求
    char http_request[4096];
    snprintf(http_request, sizeof(http_request),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        endpoint, g_config.IP, g_config.Port, strlen(encoded_data), encoded_data);
    
    // 发送请求
    if (send(sock, http_request, strlen(http_request), 0) == SOCKET_ERROR) {
        NetDeliver_DebugPrint("Send failed");
        resp->status_code = -5;
        closesocket(sock);
        WSACleanup();
        free(encoded_data);
        return resp;
    }
    
    NetDeliver_DebugPrint("Request sent");
    
    // 接收响应
    char response_buf[8192];
    int total_received = 0;
    int bytes_received;
    
    while ((bytes_received = recv(sock, response_buf + total_received, 
                                  sizeof(response_buf) - total_received - 1, 0)) > 0) {
        total_received += bytes_received;
    }
    
    response_buf[total_received] = '\0';
    
    // 解析 HTTP 响应（提取状态码和响应体）
    char *status_line = response_buf;
    int status_code = 0;
    if (sscanf(status_line, "HTTP/1.1 %d", &status_code) == 1) {
        resp->status_code = status_code;
    }
    
    // 找到响应体（HTTP 头后的空行）
    char *body_start = strstr(response_buf, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        resp->data_len = total_received - (body_start - response_buf);
        resp->data = (char *)malloc(resp->data_len + 1);
        if (resp->data) {
            strncpy(resp->data, body_start, resp->data_len);
            resp->data[resp->data_len] = '\0';
            NetDeliver_DebugPrint("Response received: %s", resp->data);
        }
    }
    
    closesocket(sock);
    WSACleanup();
    free(encoded_data);
    
    return resp;
}

// 释放 NetResponse 内存
void NetDeliver_FreeResponse(NetResponse *resp) {
    if (resp) {
        if (resp->data) free(resp->data);
        free(resp);
    }
}

/* ===== Network Request Functions ===== */
// 这里可以实现实际的网络请求函数，使用 g_config 的值
// 例如：
// int NetDeliver_SendRequest(const char *endpoint, const char *data, char *response)
// {
//     // 使用 g_config.Dist_Server, g_config.IP, g_config.Port
//     // 实现网络请求逻辑
// }
