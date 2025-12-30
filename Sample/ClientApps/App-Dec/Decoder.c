#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../NetworkHelper/NetDeliver.h"

int main(int argc, char **argv) {
    // 初始化网络配置
    NetDeliver_Init(argc, argv);
    
    // 获取配置并使用
    NetConfig *config = NetDeliver_GetConfig();
    
    // 输出结果
    if (config->IsDebug) {
        printf("--- Decoder Configuration (via NetDeliver) ---\n");
        printf("IsDebug     : %d\n", config->IsDebug);
        printf("Dist-Server : %s\n", config->Dist_Server);
        printf("IP          : %s\n", config->IP);
        printf("Port        : %s\n", config->Port);
        printf("AppPath     : %s\n", config->AppPath);
        printf("\n");
    }
    
    // 示例：向 Dist-Server 发送 JSON 请求
    const char *request_json = "{\"action\":\"decode\",\"data\":\"test_payload\"}";
    printf("Sending request: %s\n", request_json);
    
    NetResponse *resp = NetDeliver_SendRequest("/api/decode", request_json);
    if (resp) {
        printf("Response status: %d\n", resp->status_code);
        if (resp->data) {
            printf("Response data: %s\n", resp->data);
        }
        NetDeliver_FreeResponse(resp);
    }

    return 0;
}