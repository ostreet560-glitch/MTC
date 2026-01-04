#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "../openssl/rsa.h"
#include "../openssl/pem.h"
#include "../openssl/err.h"
#include "../openssl/bio.h"
#include "../openssl/evp.h"
#include "../openssl/aes.h"
#include "../NetworkHelper/NetDeliver.h"

// 从 JSON 响应中提取 RSA 私钥字段 (Base64 编码)
static int extract_rsa_key_from_json(const char *json_response, char *rsa_key, int key_size) {
    // 查找 "RSA" 字段：{"timeStamp":xxx,"RSA":"..."}
    const char *rsa_start = strstr(json_response, "\"RSA\"");
    if (!rsa_start) {
        printf("✗ RSA field not found in response\n");
        return 0;
    }
    
    // 找到 : 后的第一个 "
    const char *key_begin = strchr(rsa_start, ':');
    if (!key_begin) return 0;
    
    key_begin = strchr(key_begin, '"');
    if (!key_begin) return 0;
    key_begin++;  // 跳过开始的 "
    
    // 找到结束的 "
    const char *key_end = strchr(key_begin, '"');
    if (!key_end) return 0;
    
    int extracted_len = key_end - key_begin;
    if (extracted_len >= key_size) {
        printf("✗ RSA key too large\n");
        return 0;
    }
    
    strncpy(rsa_key, key_begin, extracted_len);
    rsa_key[extracted_len] = '\0';
    
    printf("✓ Extracted RSA private key from response\n");
    return 1;
}

// 从 JSON 响应中提取 RSA_K（加密的 AES 密钥）
static int extract_rsa_k_from_json(const char *json_response, unsigned char *rsa_k, int *rsa_k_len) {
    const char *rsa_k_start = strstr(json_response, "\"RSA_K\"");
    if (!rsa_k_start) {
        printf("✗ RSA_K field not found in response\n");
        return 0;
    }
    
    const char *key_begin = strchr(rsa_k_start, ':');
    if (!key_begin) return 0;
    
    key_begin = strchr(key_begin, '"');
    if (!key_begin) return 0;
    key_begin++;
    
    const char *key_end = strchr(key_begin, '"');
    if (!key_end) return 0;
    
    int extracted_len = key_end - key_begin;
    if (extracted_len >= 512) {
        printf("✗ RSA_K too large\n");
        return 0;
    }
    
    strncpy((char *)rsa_k, key_begin, extracted_len);
    rsa_k[extracted_len] = '\0';
    *rsa_k_len = extracted_len;
    
    printf("✓ Extracted RSA_K (encrypted AES key) from response\n");
    return 1;
}

// 从 JSON 响应中提取 IV（初始化向量）
static int extract_iv_from_json(const char *json_response, unsigned char *iv, int *iv_len) {
    const char *iv_start = strstr(json_response, "\"IV\"");
    if (!iv_start) {
        printf("⚠ IV field not found, using default IV\n");
        memset(iv, 0, 12);
        *iv_len = 12;
        return 1;
    }
    
    const char *key_begin = strchr(iv_start, ':');
    if (!key_begin) return 0;
    
    key_begin = strchr(key_begin, '"');
    if (!key_begin) return 0;
    key_begin++;
    
    const char *key_end = strchr(key_begin, '"');
    if (!key_end) return 0;
    
    int extracted_len = key_end - key_begin;
    if (extracted_len > 24) {  // Base64 12字节 = 16个字符
        printf("✗ IV too large\n");
        return 0;
    }
    
    strncpy((char *)iv, key_begin, extracted_len);
    iv[extracted_len] = '\0';
    *iv_len = extracted_len;
    
    printf("✓ Extracted IV from response\n");
    return 1;
}

// Base64 解码（简单实现）
static int base64_decode(const unsigned char *input, int input_len,
                         unsigned char *output, int *output_len) {
    BIO *bio, *b64;
    int decode_len;
    
    bio = BIO_new_mem_buf((void *)input, input_len);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    decode_len = BIO_read(bio, output, input_len);
    *output_len = decode_len;
    BIO_free_all(bio);
    
    return (decode_len > 0) ? 1 : 0;
}

// AES-256-GCM 解密
static int aes_256_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                               const unsigned char *key, const unsigned char *iv,
                               unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    // 初始化解密操作
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    // 解密数据
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    // GCM 模式下通常在这里校验 Tag (为了作业简化，此处省略 Tag 校验，生产环境必须加)
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) > 0) {
        plaintext_len += len;
    }

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// 使用 RSA 私钥解密 AES 密钥信封
static int rsa_decrypt_aes_key(const char *private_key_pem,
                               const unsigned char *encrypted_aes_key, int enc_key_len,
                               unsigned char *aes_key, int *aes_key_len) {
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t outlen = 32;
    int result = 0;
    
    bio = BIO_new_mem_buf((void *)private_key_pem, -1);
    if (!bio) {
        printf("✗ Failed to create BIO\n");
        return 0;
    }
    
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        printf("✗ Failed to read private key from PEM\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        printf("✗ Failed to create EVP_PKEY_CTX\n");
        goto cleanup;
    }
    
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        printf("✗ Failed to initialize decrypt\n");
        goto cleanup;
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        printf("✗ Failed to set RSA padding\n");
        goto cleanup;
    }
    
    if (EVP_PKEY_decrypt(ctx, aes_key, &outlen, encrypted_aes_key, enc_key_len) <= 0) {
        printf("✗ Failed to decrypt AES key envelope\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    *aes_key_len = (int)outlen;
    printf("✓ Successfully decrypted AES key (size: %d bytes)\n", *aes_key_len);
    result = 1;
    
cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (bio) BIO_free(bio);
    
    return result;
}
static char* trim_string(char *str) {
    if (!str) return "";
    while (*str && isspace((unsigned char)*str)) str++;
    char *end = str + strlen(str) - 1;
    while (end >= str && isspace((unsigned char)*end)) *end-- = '\0';
    return str;
}

// 辅助函数：从 INI 行解析键值对
static int parse_ini_line(const char *line, char *key, char *value, int key_size, int value_size) {
    const char *eq = strchr(line, '=');
    if (!eq) return 0;
    
    int key_len = eq - line;
    if (key_len >= key_size) return 0;
    
    strncpy(key, line, key_len);
    key[key_len] = '\0';
    strcpy(key, trim_string(key));
    
    const char *val_start = eq + 1;
    if (*val_start == '"') val_start++;
    const char *val_end = strchr(val_start, '"');
    if (val_end) {
        int val_len = val_end - val_start;
        if (val_len >= value_size) return 0;
        strncpy(value, val_start, val_len);
        value[val_len] = '\0';
    } else {
        strncpy(value, val_start, value_size - 1);
        value[value_size - 1] = '\0';
    }
    strcpy(value, trim_string(value));
    return 1;
}

// 直接从 AkiTools.ini 读取 AppPath
static int read_apppath_from_ini(const char *ini_path, char *apppath, int apppath_size) {
    FILE *f = fopen(ini_path, "r");
    if (!f) {
        printf("✗ Failed to open AkiTools.ini: %s\n", ini_path);
        return 0;
    }
    
    char line[1024];
    int in_debug_section = 0;
    int found = 0;
    
    while (fgets(line, sizeof(line), f)) {
        char *ln = trim_string(line);
        
        // 检查 [Debug] 部分
        if (ln[0] == '[') {
            in_debug_section = (strstr(ln, "[Debug]") != NULL);
            continue;
        }
        
        if (in_debug_section && ln[0] != ';') {
            char key[256], value[512];
            if (parse_ini_line(ln, key, value, sizeof(key), sizeof(value))) {
                if (_stricmp(key, "AppPath") == 0) {
                    strncpy(apppath, value, apppath_size - 1);
                    apppath[apppath_size - 1] = '\0';
                    found = 1;
                    break;
                }
            }
        }
    }
    
    fclose(f);
    return found;
}

int main(int argc, char **argv) {
    // 初始化网络配置
    NetDeliver_Init(argc, argv);
    
    // 获取配置
    NetConfig *config = NetDeliver_GetConfig();
    
    // 输出结果
    if (config->IsDebug) {
        printf("--- Decryptor Configuration (via NetDeliver) ---\n");
        printf("IsDebug     : %d\n", config->IsDebug);
        printf("Dist-Server : %s\n", config->Dist_Server);
        printf("IP          : %s\n", config->IP);
        printf("Port        : %s\n", config->Port);
        printf("AppPath     : %s\n", config->AppPath);
        printf("\n");
        
            // Debug 模式下：直接访问 AkiTools.ini 中的 AppPath 字段
        printf("--- Debug Mode: Direct AkiTools.ini Access ---\n");
        char apppath_from_ini[512] = {0};
        
        // 默认路径
        strcpy(apppath_from_ini, "..\\main.exe");
        
        // 仅在 IsDebug=1 时允许读取 INI 文件
        char ini_apppath[512] = {0};
        if (read_apppath_from_ini("../../AkiTools.ini", ini_apppath, sizeof(ini_apppath))) {
            strcpy(apppath_from_ini, ini_apppath);
            printf("✓ AppPath from AkiTools.ini: %s\n", apppath_from_ini);
        } else {
            printf("⚠ Using default AppPath: %s\n", apppath_from_ini);
        }
        
        // 重定向：验证应用程序路径
        FILE *app_file = fopen(apppath_from_ini, "rb");
        if (app_file) {
            printf("✓ Target application found: %s\n", apppath_from_ini);
            fclose(app_file);
        } else {
            printf("✗ Target application NOT found: %s\n", apppath_from_ini);
        }
        printf("\n");
    }
    
    // 获取当前 Unix 时间戳
    time_t current_time = time(NULL);
    
    // 构造请求 JSON: {timeStamp, reqCode=22}
    // reqCode=22: 获取主程序解密密钥
    char request_json[512];
    snprintf(request_json, sizeof(request_json),
             "{\"timeStamp\":%ld,\"reqCode\":22}",
             (long)current_time);
    
    printf("Sending request: %s\n", request_json);
    
    NetResponse *resp = NetDeliver_SendRequest("/api/decrypt", request_json);
    if (resp) {
        printf("Response status: %d\n", resp->status_code);
        if (resp->data) {
            printf("Response data: %s\n\n", resp->data);
            
            // 从 JSON 响应中提取数字信封组件：
            // {"timeStamp":xxx, "RSA_K":"encrypted_aes_key", "IV":"initialization_vector"}
            
            // 1. 提取 RSA 私钥（用于解密 AES 密钥信封）
            char private_key_pem[4096] = {0};
            if (!extract_rsa_key_from_json(resp->data, private_key_pem, sizeof(private_key_pem))) {
                printf("✗ Failed to extract RSA private key from response\n");
                NetDeliver_FreeResponse(resp);
                return 1;
            }
            
            // 2. 提取加密的 AES 密钥（RSA_K）
            unsigned char rsa_k_b64[512] = {0};
            int rsa_k_b64_len = 0;
            if (!extract_rsa_k_from_json(resp->data, rsa_k_b64, &rsa_k_b64_len)) {
                printf("✗ Failed to extract RSA_K from response\n");
                NetDeliver_FreeResponse(resp);
                return 1;
            }
            
            // 解码 Base64 的加密 AES 密钥
            unsigned char rsa_k_binary[256] = {0};
            int rsa_k_binary_len = 0;
            if (!base64_decode(rsa_k_b64, rsa_k_b64_len, rsa_k_binary, &rsa_k_binary_len)) {
                printf("✗ Failed to decode RSA_K from Base64\n");
                NetDeliver_FreeResponse(resp);
                return 1;
            }
            
            // 3. 提取 IV（初始化向量）
            unsigned char iv[16] = {0};
            int iv_len = 0;
            extract_iv_from_json(resp->data, iv, &iv_len);
            
            // 4. 使用 RSA 私钥解密 AES 密钥（打开数字信封）
            unsigned char aes_key[32] = {0};
            int aes_key_len = 0;
            if (!rsa_decrypt_aes_key(private_key_pem, rsa_k_binary, rsa_k_binary_len, 
                                     aes_key, &aes_key_len)) {
                printf("✗ Failed to decrypt AES key envelope\n");
                NetDeliver_FreeResponse(resp);
                return 1;
            }
            
            if (config->IsDebug) {
                printf("\n--- Two-Layer Decryption (Digital Envelope) ---\n");
                printf("AES Key unlocked: %d bytes\n", aes_key_len);
                printf("IV length: %d bytes\n", iv_len);
            }
            
            // 5. 读取加密的应用程序文件
            char app_path[512] = "..\\main.exe";
            if (config->IsDebug) {
                char ini_apppath[512] = {0};
                if (read_apppath_from_ini("../../AkiTools.ini", ini_apppath, sizeof(ini_apppath))) {
                    strcpy(app_path, ini_apppath);
                }
            }
            
            FILE *encrypted_file = fopen(app_path, "rb");
            if (!encrypted_file) {
                printf("✗ Failed to open encrypted app: %s\n", app_path);
                NetDeliver_FreeResponse(resp);
                return 1;
            }
            
            // 获取文件大小
            fseek(encrypted_file, 0, SEEK_END);
            long file_size = ftell(encrypted_file);
            fseek(encrypted_file, 0, SEEK_SET);
            
            unsigned char *encrypted_data = (unsigned char *)malloc(file_size);
            unsigned char *decrypted_data = (unsigned char *)malloc(file_size + 256);
            
            if (fread(encrypted_data, 1, file_size, encrypted_file) != file_size) {
                printf("✗ Failed to read encrypted app file\n");
                free(encrypted_data);
                free(decrypted_data);
                fclose(encrypted_file);
                NetDeliver_FreeResponse(resp);
                return 1;
            }
            fclose(encrypted_file);
            
            // 6. 使用解开的 AES 密钥进行 AES-256-GCM 对称解密
            printf("\n--- Starting AES-256-GCM Decryption ---\n");
            int decrypted_size = aes_256_gcm_decrypt(encrypted_data, (int)file_size, 
                                                     aes_key, iv, decrypted_data);
            
            if (decrypted_size > 0) {
                printf("✓ AES-256-GCM decryption successful\n");
                printf("Decrypted size: %d bytes\n", decrypted_size);
                
                // 7. 写入解密后的文件
                char output_path[512];
                snprintf(output_path, sizeof(output_path), "%s.decrypted", app_path);
                
                FILE *decrypted_file = fopen(output_path, "wb");
                if (decrypted_file) {
                    if (fwrite(decrypted_data, 1, decrypted_size, decrypted_file) == decrypted_size) {
                        printf("✓ Decrypted app saved: %s\n", output_path);
                    } else {
                        printf("✗ Failed to write decrypted app\n");
                    }
                    fclose(decrypted_file);
                } else {
                    printf("✗ Failed to create decrypted app file\n");
                }
            } else {
                printf("✗ AES-256-GCM decryption failed\n");
            }
            
            free(encrypted_data);
            free(decrypted_data);
        }
        NetDeliver_FreeResponse(resp);
    }

    return 0;
}