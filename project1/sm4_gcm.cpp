#include <iostream>
#include <vector>
#include <cstring>
#include <immintrin.h>  // 用于SIMD指令集优化
#include <wmmintrin.h>  // 用于AES-NI指令（可用于GHASH优化）

// SM4算法常量定义
constexpr uint32_t SM4_FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};
constexpr uint32_t SM4_CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// 左循环移位
inline uint32_t SM4_ROTL(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// S盒变换
inline uint32_t SM4_TAU(uint32_t x) {
    const uint8_t SBOX[256] = {
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    };
    
    uint8_t b[4];
    b[0] = SBOX[(x >> 24) & 0xFF];
    b[1] = SBOX[(x >> 16) & 0xFF];
    b[2] = SBOX[(x >> 8) & 0xFF];
    b[3] = SBOX[x & 0xFF];
    
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
}

// 线性变换L
inline uint32_t SM4_L(uint32_t x) {
    return x ^ SM4_ROTL(x, 2) ^ SM4_ROTL(x, 10) ^ SM4_ROTL(x, 18) ^ SM4_ROTL(x, 24);
}

// 合成变换T
inline uint32_t SM4_T(uint32_t x) {
    return SM4_L(SM4_TAU(x));
}

// 轮函数F
inline uint32_t SM4_F(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {
    return x0 ^ SM4_T(x1 ^ x2 ^ x3 ^ rk);
}

// SM4密钥扩展
void SM4_KeySchedule(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t MK[4];
    for (int i = 0; i < 4; ++i) {
        MK[i] = (key[i*4] << 24) | (key[i*4+1] << 16) | (key[i*4+2] << 8) | key[i*4+3];
    }
    
    uint32_t K[36];
    for (int i = 0; i < 4; ++i) {
        K[i] = MK[i] ^ SM4_FK[i];
    }
    
    for (int i = 0; i < 32; ++i) {
        K[i+4] = K[i] ^ SM4_T(K[i+1] ^ K[i+2] ^ K[i+3] ^ SM4_CK[i]);
        rk[i] = K[i+4];
    }
}

// SM4加密/解密（解密与加密相同，只是轮密钥逆序使用）
void SM4_Crypt(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16], bool encrypt = true) {
    uint32_t X[36];
    for (int i = 0; i < 4; ++i) {
        X[i] = (in[i*4] << 24) | (in[i*4+1] << 16) | (in[i*4+2] << 8) | in[i*4+3];
    }
    
    for (int i = 0; i < 32; ++i) {
        int rk_idx = encrypt ? i : (31 - i);
        X[i+4] = SM4_F(X[i], X[i+1], X[i+2], X[i+3], rk[rk_idx]);
    }
    
    for (int i = 0; i < 4; ++i) {
        out[i*4] = (X[35-i] >> 24) & 0xFF;
        out[i*4+1] = (X[35-i] >> 16) & 0xFF;
        out[i*4+2] = (X[35-i] >> 8) & 0xFF;
        out[i*4+3] = X[35-i] & 0xFF;
    }
}

// GCM模式相关函数
class SM4_GCM {
private:
    uint32_t rk[32];  // SM4轮密钥
    uint8_t H[16];    // 加密的零块，用于GHASH
    uint8_t J0[16];   // 初始计数器
    
    // 使用SIMD优化的GHASH乘法
    void ghash_multiply(uint8_t X[16], const uint8_t Y[16]) {
        // 这里可以使用AES-NI指令优化GHASH乘法
        // 由于SM4和AES的GCM模式GHASH相同，可以复用这部分优化
        
        __m128i x = _mm_loadu_si128((__m128i*)X);
        __m128i y = _mm_loadu_si128((__m128i*)Y);
        __m128i h = _mm_loadu_si128((__m128i*)H);
        
        // 使用AES-NI指令实现GF(2^128)乘法
        __m128i z = _mm_clmulepi64_si128(x, h, 0x00);
        __m128i t = _mm_clmulepi64_si128(x, h, 0x11);
        __m128i v = _mm_clmulepi64_si128(x, h, 0x01);
        v = _mm_xor_si128(v, _mm_clmulepi64_si128(x, h, 0x10));
        
        __m128i tmp = _mm_slli_si128(v, 8);
        z = _mm_xor_si128(z, tmp);
        tmp = _mm_srli_si128(v, 8);
        t = _mm_xor_si128(t, tmp);
        
        // 模约简
        __m128i p = _mm_set_epi32(0, 0, 0, 0x87);
        v = _mm_clmulepi64_si128(t, p, 0x01);
        tmp = _mm_slli_si128(v, 8);
        z = _mm_xor_si128(z, tmp);
        v = _mm_clmulepi64_si128(t, p, 0x00);
        tmp = _mm_srli_si128(v, 8);
        z = _mm_xor_si128(z, tmp);
        
        _mm_storeu_si128((__m128i*)X, z);
    }
    
    // 计算GHASH
    void ghash(const uint8_t* aad, size_t aad_len, const uint8_t* ciphertext, size_t ciphertext_len, uint8_t output[16]) {
        uint8_t X[16] = {0};
        size_t len;
        
        // 处理附加认证数据(AAD)
        if (aad_len > 0) {
            len = 0;
            while (len + 16 <= aad_len) {
                for (int i = 0; i < 16; ++i) {
                    X[i] ^= aad[len + i];
                }
                ghash_multiply(X, H);
                len += 16;
            }
            
            if (len < aad_len) {
                size_t remaining = aad_len - len;
                uint8_t block[16] = {0};
                memcpy(block, aad + len, remaining);
                for (int i = 0; i < 16; ++i) {
                    X[i] ^= block[i];
                }
                ghash_multiply(X, H);
            }
        }
        
        // 处理密文
        if (ciphertext_len > 0) {
            len = 0;
            while (len + 16 <= ciphertext_len) {
                for (int i = 0; i < 16; ++i) {
                    X[i] ^= ciphertext[len + i];
                }
                ghash_multiply(X, H);
                len += 16;
            }
            
            if (len < ciphertext_len) {
                size_t remaining = ciphertext_len - len;
                uint8_t block[16] = {0};
                memcpy(block, ciphertext + len, remaining);
                for (int i = 0; i < 16; ++i) {
                    X[i] ^= block[i];
                }
                ghash_multiply(X, H);
            }
        }
        
        // 添加长度信息 (AAD长度 || 密文长度)
        uint8_t len_block[16] = {0};
        uint64_t aad_bits = aad_len * 8;
        uint64_t cipher_bits = ciphertext_len * 8;
        
        for (int i = 0; i < 8; ++i) {
            len_block[i] = (aad_bits >> (56 - i * 8)) & 0xFF;
            len_block[i + 8] = (cipher_bits >> (56 - i * 8)) & 0xFF;
        }
        
        for (int i = 0; i < 16; ++i) {
            X[i] ^= len_block[i];
        }
        ghash_multiply(X, H);
        
        memcpy(output, X, 16);
    }
    
    // 递增计数器
    void increment_counter(uint8_t ctr[16]) {
        for (int i = 15; i >= 12; --i) {
            ctr[i]++;
            if (ctr[i] != 0) break;
        }
    }
    
public:
    SM4_GCM(const uint8_t key[16], const uint8_t iv[12]) {
        // 生成轮密钥
        SM4_KeySchedule(key, rk);
        
        // 计算H = SM4_Encrypt(0^128)
        uint8_t zero[16] = {0};
        SM4_Crypt(rk, zero, H);
        
        // 生成J0
        if (iv != nullptr) {
            // 对于12字节IV，J0 = IV || 0x00000001
            memcpy(J0, iv, 12);
            J0[12] = J0[13] = J0[14] = 0;
            J0[15] = 1;
        } else {
            // 如果没有提供IV，生成全零IV
            memset(J0, 0, 16);
        }
    }
    
    // 认证加密
    void encrypt(const uint8_t* plaintext, size_t plaintext_len,
                const uint8_t* aad, size_t aad_len,
                uint8_t* ciphertext, uint8_t tag[16]) {
        uint8_t ctr[16];
        memcpy(ctr, J0, 16);
        increment_counter(ctr);  // 第一次递增，因为J0用于GHASH
        
        // 加密plaintext
        size_t len = 0;
        while (len + 16 <= plaintext_len) {
            uint8_t keystream[16];
            SM4_Crypt(rk, ctr, keystream);
            
            for (int i = 0; i < 16; ++i) {
                ciphertext[len + i] = plaintext[len + i] ^ keystream[i];
            }
            
            increment_counter(ctr);
            len += 16;
        }
        
        // 处理最后一个不完整的块
        if (len < plaintext_len) {
            uint8_t keystream[16];
            SM4_Crypt(rk, ctr, keystream);
            
            size_t remaining = plaintext_len - len;
            for (size_t i = 0; i < remaining; ++i) {
                ciphertext[len + i] = plaintext[len + i] ^ keystream[i];
            }
        }
        
        // 计算认证标签
        uint8_t S[16];
        ghash(aad, aad_len, ciphertext, plaintext_len, S);
        
        uint8_t T[16];
        SM4_Crypt(rk, J0, T);
        
        for (int i = 0; i < 16; ++i) {
            tag[i] = S[i] ^ T[i];
        }
    }
    
    // 认证解密
    bool decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                const uint8_t* aad, size_t aad_len,
                const uint8_t tag[16],
                uint8_t* plaintext) {
        // 首先验证标签
        uint8_t S[16];
        ghash(aad, aad_len, ciphertext, ciphertext_len, S);
        
        uint8_t T[16];
        SM4_Crypt(rk, J0, T);
        
        uint8_t computed_tag[16];
        for (int i = 0; i < 16; ++i) {
            computed_tag[i] = S[i] ^ T[i];
        }
        
        bool tag_valid = true;
        for (int i = 0; i < 16; ++i) {
            if (computed_tag[i] != tag[i]) {
                tag_valid = false;
                break;
            }
        }
        
        if (!tag_valid) {
            return false;
        }
        
        // 标签验证通过，解密数据
        uint8_t ctr[16];
        memcpy(ctr, J0, 16);
        increment_counter(ctr);  // 第一次递增，因为J0用于GHASH
        
        size_t len = 0;
        while (len + 16 <= ciphertext_len) {
            uint8_t keystream[16];
            SM4_Crypt(rk, ctr, keystream);
            
            for (int i = 0; i < 16; ++i) {
                plaintext[len + i] = ciphertext[len + i] ^ keystream[i];
            }
            
            increment_counter(ctr);
            len += 16;
        }
        
        // 处理最后一个不完整的块
        if (len < ciphertext_len) {
            uint8_t keystream[16];
            SM4_Crypt(rk, ctr, keystream);
            
            size_t remaining = ciphertext_len - len;
            for (size_t i = 0; i < remaining; ++i) {
                plaintext[len + i] = ciphertext[len + i] ^ keystream[i];
            }
        }
        
        return true;
    }
};

// 测试函数
void test_sm4_gcm() {
    // 测试向量来自GM/T 0002-2012 SM4标准附录A
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    uint8_t iv[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b
    };
    
    uint8_t plaintext[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    uint8_t aad[20] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa
    };
    
    SM4_GCM sm4_gcm(key, iv);
    
    uint8_t ciphertext[32];
    uint8_t tag[16];
    
    std::cout << "测试SM4-GCM加密..." << std::endl;
    sm4_gcm.encrypt(plaintext, sizeof(plaintext), aad, sizeof(aad), ciphertext, tag);
    
    std::cout << "密文: ";
    for (int i = 0; i < 32; ++i) {
        printf("%02x ", ciphertext[i]);
    }
    std::cout << std::endl;
    
    std::cout << "认证标签: ";
    for (int i = 0; i < 16; ++i) {
        printf("%02x ", tag[i]);
    }
    std::cout << std::endl;
    
    std::cout << "测试SM4-GCM解密..." << std::endl;
    uint8_t decrypted[32];
    bool success = sm4_gcm.decrypt(ciphertext, sizeof(ciphertext), aad, sizeof(aad), tag, decrypted);
    
    if (success) {
        std::cout << "解密成功!" << std::endl;
        std::cout << "解密后的明文: ";
        for (int i = 0; i < 32; ++i) {
            printf("%02x ", decrypted[i]);
        }
        std::cout << std::endl;
        
        // 验证解密结果是否与原始明文匹配
        bool match = true;
        for (int i = 0; i < 32; ++i) {
            if (decrypted[i] != plaintext[i]) {
                match = false;
                break;
            }
        }
        
        if (match) {
            std::cout << "解密后的明文与原始明文一致!" << std::endl;
        } else {
            std::cout << "解密后的明文与原始明文不一致!" << std::endl;
        }
    } else {
        std::cout << "解密失败 - 认证标签验证未通过!" << std::endl;
    }
    
    // 测试篡改检测
    std::cout << "测试篡改检测功能..." << std::endl;
    uint8_t tampered_tag[16];
    memcpy(tampered_tag, tag, 16);
    tampered_tag[0] ^= 0x01;  // 翻转一个bit
    
    bool tamper_success = sm4_gcm.decrypt(ciphertext, sizeof(ciphertext), aad, sizeof(aad), tampered_tag, decrypted);
    if (!tamper_success) {
        std::cout << "成功检测到数据被篡改!" << std::endl;
    } else {
        std::cout << "未能检测到数据篡改!" << std::endl;
    }
}

int main() {
    test_sm4_gcm();
    return 0;
}
