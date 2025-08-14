#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <immintrin.h>

// 通用宏定义
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// 布尔函数宏
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

// 置换函数宏
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

// SM3常量
static const uint32_t T[64] = {
    0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB,
    0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC,
    0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE,
    0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6,
    0x451979CC, 0x8A32F398, 0x1465E731, 0x28CBCE62,
    0x51979CC4, 0xA32F3988, 0x465E7311, 0x8CBCE622,
    0x1979CC45, 0x32F3988A, 0x65E73114, 0xCBCE6228,
    0x979CC451, 0x2F3988A3, 0x5E731146, 0xBCE6228C,
    0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB,
    0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC,
    0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE,
    0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6,
    0x451979CC, 0x8A32F398, 0x1465E731, 0x28CBCE62,
    0x51979CC4, 0xA32F3988, 0x465E7311, 0x8CBCE622,
    0x1979CC45, 0x32F3988A, 0x65E73114, 0xCBCE6228
};

// 基本实现
void sm3_compress_basic(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68];
    uint32_t W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    int j;
    
    // 消息扩展
    for (j = 0; j < 16; j++) {
        W[j] = ((uint32_t)block[j * 4] << 24) | 
               ((uint32_t)block[j * 4 + 1] << 16) | 
               ((uint32_t)block[j * 4 + 2] << 8) | 
               ((uint32_t)block[j * 4 + 3]);
    }
    
    for (j = 16; j < 68; j++) {
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3], 15)) ^ ROTL(W[j-13], 7) ^ W[j-6];
    }
    
    for (j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j+4];
    }
    
    // 压缩函数
    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];
    
    for (j = 0; j < 64; j++) {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        
        if (j < 16) {
            TT1 = FF0(A, B, C) + D + SS2 + W1[j];
            TT2 = GG0(E, F, G) + H + SS1 + W[j];
        } else {
            TT1 = FF1(A, B, C) + D + SS2 + W1[j];
            TT2 = GG1(E, F, G) + H + SS1 + W[j];
        }
        
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }
    
    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

// 优化1：循环展开和常量预计算
void sm3_compress_opt1(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68];
    uint32_t W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    
    // 消息扩展 (部分展开)
    for (int j = 0; j < 16; j++) {
        W[j] = ((uint32_t)block[j * 4] << 24) | 
               ((uint32_t)block[j * 4 + 1] << 16) | 
               ((uint32_t)block[j * 4 + 2] << 8) | 
               ((uint32_t)block[j * 4 + 3]);
    }
    
    // 展开部分循环
    for (int j = 16; j < 68; j += 4) {
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3], 15)) ^ ROTL(W[j-13], 7) ^ W[j-6];
        W[j+1] = P1(W[j-15] ^ W[j-8] ^ ROTL(W[j-2], 15)) ^ ROTL(W[j-12], 7) ^ W[j-5];
        W[j+2] = P1(W[j-14] ^ W[j-7] ^ ROTL(W[j-1], 15)) ^ ROTL(W[j-11], 7) ^ W[j-4];
        W[j+3] = P1(W[j-13] ^ W[j-6] ^ ROTL(W[j], 15)) ^ ROTL(W[j-10], 7) ^ W[j-3];
    }
    
    // 预计算W1
    for (int j = 0; j < 64; j += 4) {
        W1[j] = W[j] ^ W[j+4];
        W1[j+1] = W[j+1] ^ W[j+5];
        W1[j+2] = W[j+2] ^ W[j+6];
        W1[j+3] = W[j+3] ^ W[j+7];
    }
    
    // 压缩函数 (部分展开)
    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];
    
    // 前16轮
    for (int j = 0; j < 16; j++) {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF0(A, B, C) + D + SS2 + W1[j];
        TT2 = GG0(E, F, G) + H + SS1 + W[j];
        
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }
    
    // 后48轮
    for (int j = 16; j < 64; j++) {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF1(A, B, C) + D + SS2 + W1[j];
        TT2 = GG1(E, F, G) + H + SS1 + W[j];
        
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }
    
    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

// 优化2：使用查表法优化布尔函数
void sm3_compress_opt2(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68];
    uint32_t W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    
    // 消息扩展
    for (int j = 0; j < 16; j++) {
        W[j] = ((uint32_t)block[j * 4] << 24) | 
               ((uint32_t)block[j * 4 + 1] << 16) | 
               ((uint32_t)block[j * 4 + 2] << 8) | 
               ((uint32_t)block[j * 4 + 3]);
    }
    
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3], 15)) ^ ROTL(W[j-13], 7) ^ W[j-6];
    }
    
    for (int j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j+4];
    }
    
    // 压缩函数
    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];
    
    for (int j = 0; j < 64; j++) {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        
        if (j < 16) {
            // 直接计算FF0和GG0，查表法不适合32位操作
            TT1 = FF0(A, B, C) + D + SS2 + W1[j];
            TT2 = GG0(E, F, G) + H + SS1 + W[j];
        } else {
            // 直接计算FF1和GG1，查表法不适合32位操作
            TT1 = FF1(A, B, C) + D + SS2 + W1[j];
            TT2 = GG1(E, F, G) + H + SS1 + W[j];
        }
        
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }
    
    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

// 优化3：SIMD指令并行化
#ifdef __AVX2__
void sm3_compress_opt3(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68];
    uint32_t W1[64];
    __m128i A, B, C, D, E, F, G, H;
    __m128i SS1, SS2, TT1, TT2;
    __m128i tmp1, tmp2, tmp3, tmp4;
    
    // 消息扩展
    for (int j = 0; j < 16; j++) {
        W[j] = ((uint32_t)block[j * 4] << 24) | 
               ((uint32_t)block[j * 4 + 1] << 16) | 
               ((uint32_t)block[j * 4 + 2] << 8) | 
               ((uint32_t)block[j * 4 + 3]);
    }
    
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3], 15)) ^ ROTL(W[j-13], 7) ^ W[j-6];
    }
    
    for (int j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j+4];
    }
    
    // 初始化状态 (使用SIMD寄存器)
    A = _mm_set1_epi32(state[0]);
    B = _mm_set1_epi32(state[1]);
    C = _mm_set1_epi32(state[2]);
    D = _mm_set1_epi32(state[3]);
    E = _mm_set1_epi32(state[4]);
    F = _mm_set1_epi32(state[5]);
    G = _mm_set1_epi32(state[6]);
    H = _mm_set1_epi32(state[7]);
    
    for (int j = 0; j < 64; j++) {
        // 计算SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7)
        tmp1 = _mm_or_si128(_mm_slli_epi32(A, 12), _mm_srli_epi32(A, 20));
        tmp2 = _mm_add_epi32(tmp1, E);
        tmp3 = _mm_or_si128(_mm_slli_epi32(_mm_set1_epi32(T[j]), j % 32), 
                           _mm_srli_epi32(_mm_set1_epi32(T[j]), (32 - j % 32)));
        tmp2 = _mm_add_epi32(tmp2, tmp3);
        SS1 = _mm_or_si128(_mm_slli_epi32(tmp2, 7), _mm_srli_epi32(tmp2, 25));
        
        // 计算SS2 = SS1 ^ ROTL(A,12)
        SS2 = _mm_xor_si128(SS1, tmp1);
        
        // 计算TT1和TT2
        if (j < 16) {
            // FF0: x ^ y ^ z
            tmp1 = _mm_xor_si128(A, B);
            tmp1 = _mm_xor_si128(tmp1, C);
            
            // GG0: x ^ y ^ z
            tmp2 = _mm_xor_si128(E, F);
            tmp2 = _mm_xor_si128(tmp2, G);
        } else {
            // FF1: (x & y) | (x & z) | (y & z)
            tmp3 = _mm_and_si128(A, B);
            tmp4 = _mm_and_si128(A, C);
            tmp1 = _mm_or_si128(tmp3, tmp4);
            tmp3 = _mm_and_si128(B, C);
            tmp1 = _mm_or_si128(tmp1, tmp3);
            
            // GG1: (x & y) | (~x & z)
            tmp3 = _mm_and_si128(E, F);
            tmp4 = _mm_andnot_si128(E, G);
            tmp2 = _mm_or_si128(tmp3, tmp4);
        }
        
        TT1 = _mm_add_epi32(tmp1, D);
        TT1 = _mm_add_epi32(TT1, SS2);
        TT1 = _mm_add_epi32(TT1, _mm_set1_epi32(W1[j]));
        
        TT2 = _mm_add_epi32(tmp2, H);
        TT2 = _mm_add_epi32(TT2, SS1);
        TT2 = _mm_add_epi32(TT2, _mm_set1_epi32(W[j]));
        
        // 更新状态
        D = C;
        C = _mm_or_si128(_mm_slli_epi32(B, 9), _mm_srli_epi32(B, 23));
        B = A;
        A = TT1;
        H = G;
        G = _mm_or_si128(_mm_slli_epi32(F, 19), _mm_srli_epi32(F, 13));
        F = E;
        
        // E = P0(TT2) = TT2 ^ ROTL(TT2,9) ^ ROTL(TT2,17)
        tmp1 = _mm_or_si128(_mm_slli_epi32(TT2, 9), _mm_srli_epi32(TT2, 23));
        tmp2 = _mm_or_si128(_mm_slli_epi32(TT2, 17), _mm_srli_epi32(TT2, 15));
        E = _mm_xor_si128(TT2, tmp1);
        E = _mm_xor_si128(E, tmp2);
    }
    
    // 将SIMD寄存器结果存回状态
    uint32_t tmp[4];
    _mm_storeu_si128((__m128i*)tmp, A);
    state[0] ^= tmp[0];
    _mm_storeu_si128((__m128i*)tmp, B);
    state[1] ^= tmp[0];
    _mm_storeu_si128((__m128i*)tmp, C);
    state[2] ^= tmp[0];
    _mm_storeu_si128((__m128i*)tmp, D);
    state[3] ^= tmp[0];
    _mm_storeu_si128((__m128i*)tmp, E);
    state[4] ^= tmp[0];
    _mm_storeu_si128((__m128i*)tmp, F);
    state[5] ^= tmp[0];
    _mm_storeu_si128((__m128i*)tmp, G);
    state[6] ^= tmp[0];
    _mm_storeu_si128((__m128i*)tmp, H);
    state[7] ^= tmp[0];
}
#endif

// 通用的SM3哈希函数，可选择不同的压缩函数实现
void sm3_hash(const uint8_t *msg, size_t len, uint8_t digest[32], int opt_level) {
    uint32_t state[8] = {
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };
    
    size_t block_len = 64;
    size_t pad_len = (block_len - (len + 1 + 8) % block_len) % block_len;
    size_t total_len = len + 1 + pad_len + 8;
    uint8_t *padded_msg = (uint8_t *)malloc(total_len);
    
    memcpy(padded_msg, msg, len);
    padded_msg[len] = 0x80;
    memset(padded_msg + len + 1, 0, pad_len);
    
    uint64_t bit_len = len * 8;
    for (int i = 0; i < 8; i++) {
        padded_msg[total_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xFF;
    }
    
    // 根据优化级别选择不同的压缩函数
    void (*compress_func)(uint32_t[8], const uint8_t[64]);
    switch (opt_level) {
        case 1:
            compress_func = sm3_compress_opt1;
            break;
        case 2:
            compress_func = sm3_compress_opt2;
            break;
#ifdef __AVX2__
        case 3:
            compress_func = sm3_compress_opt3;
            break;
#endif
        default:
            compress_func = sm3_compress_basic;
    }
    
    for (size_t i = 0; i < total_len; i += block_len) {
        compress_func(state, padded_msg + i);
    }
    
    free(padded_msg);
    
    for (int i = 0; i < 8; i++) {
        digest[i * 4] = (state[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = state[i] & 0xFF;
    }
}

// 高精度计时函数（微秒级）
double get_current_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

// 修改后的测试函数
void test_implementations() {
    const char *test_msg = "abc";
    size_t msg_len = strlen(test_msg);
    uint8_t digest[32];
    double start_time, end_time;
    const int TEST_ITERATIONS = 100000; // 增加迭代次数以获得更准确的时间
    
    printf("Testing SM3 with message: \"%s\" (averaged over %d iterations)\n", 
           test_msg, TEST_ITERATIONS);

    // 测试基本实现
    start_time = get_current_time();
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        sm3_hash((const uint8_t *)test_msg, msg_len, digest, 0);
    }
    end_time = get_current_time();
    
    printf("\nBasic implementation:\n");
    printf("Hash result: ");
    for (int i = 0; i < 32; i++) printf("%02x", digest[i]);
    printf("\nTime used: %.6f sec (%.3f us per hash)\n", 
           end_time - start_time, 
           (end_time - start_time) * 1000000 / TEST_ITERATIONS);

    // 测试优化1
    start_time = get_current_time();
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        sm3_hash((const uint8_t *)test_msg, msg_len, digest, 1);
    }
    end_time = get_current_time();
    
    printf("\nOptimization 1 (loop unrolling):\n");
    printf("Hash result: ");
    for (int i = 0; i < 32; i++) printf("%02x", digest[i]);
    printf("\nTime used: %.6f sec (%.3f us per hash)\n", 
           end_time - start_time, 
           (end_time - start_time) * 1000000 / TEST_ITERATIONS);

    // 测试优化2
    start_time = get_current_time();
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        sm3_hash((const uint8_t *)test_msg, msg_len, digest, 2);
    }
    end_time = get_current_time();
    
    printf("\nOptimization 2 (corrected):\n");
    printf("Hash result: ");
    for (int i = 0; i < 32; i++) printf("%02x", digest[i]);
    printf("\nTime used: %.6f sec (%.3f us per hash)\n", 
           end_time - start_time, 
           (end_time - start_time) * 1000000 / TEST_ITERATIONS);

#ifdef __AVX2__
    // 测试优化3
    start_time = get_current_time();
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        sm3_hash((const uint8_t *)test_msg, msg_len, digest, 3);
    }
    end_time = get_current_time();
    
    printf("\nOptimization 3 (SIMD):\n");
    printf("Hash result: ");
    for (int i = 0; i < 32; i++) printf("%02x", digest[i]);
    printf("\nTime used: %.6f sec (%.3f us per hash)\n", 
           end_time - start_time, 
           (end_time - start_time) * 1000000 / TEST_ITERATIONS);
#else
    printf("\nOptimization 3 (SIMD): Not supported on this platform\n");
#endif
}
// 性能测试函数
void test_performance() {
    const size_t TEST_SIZE = 1024 * 1024; // 1MB
    const int TEST_ITERATIONS = 100;
    
    uint8_t *data = (uint8_t *)malloc(TEST_SIZE);
    uint8_t digest[32];
    clock_t start, end;
    double time_used;
    
    // 初始化测试数据
    for (size_t i = 0; i < TEST_SIZE; i++) {
        data[i] = (uint8_t)(i % 256);
    }
    
    printf("Performance testing with %d MB of data...\n", (int)(TEST_SIZE * TEST_ITERATIONS / (1024 * 1024)));
    
    // 测试基本实现
    start = clock();
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        sm3_hash(data, TEST_SIZE, digest, 0);
    }
    end = clock();
    time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Basic implementation: %.2f MB/s\n", 
           (TEST_SIZE * TEST_ITERATIONS) / (time_used * 1024 * 1024));
    
    // 测试优化1
    start = clock();
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        sm3_hash(data, TEST_SIZE, digest, 1);
    }
    end = clock();
    time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Optimization 1 (loop unrolling): %.2f MB/s\n", 
           (TEST_SIZE * TEST_ITERATIONS) / (time_used * 1024 * 1024));
    
    // 测试优化2
    start = clock();
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        sm3_hash(data, TEST_SIZE, digest, 2);
    }
    end = clock();
    time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Optimization 2 (lookup tables): %.2f MB/s\n", 
           (TEST_SIZE * TEST_ITERATIONS) / (time_used * 1024 * 1024));
    
#ifdef __AVX2__
    // 测试优化3
    start = clock();
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        sm3_hash(data, TEST_SIZE, digest, 3);
    }
    end = clock();
    time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Optimization 3 (SIMD): %.2f MB/s\n", 
           (TEST_SIZE * TEST_ITERATIONS) / (time_used * 1024 * 1024));
#else
    printf("Optimization 3 (SIMD): Not supported on this platform\n");
#endif
    
    free(data);
}

int main() {
    // 测试各实现版本
    test_implementations();
    
    // 性能测试
    printf("\nStarting performance test with larger data...\n");
    test_performance();
    
    return 0;
}
