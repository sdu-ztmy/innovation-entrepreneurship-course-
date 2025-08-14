#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// SM3 常量定义
#define ROTL(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define FF0(x,y,z) ((x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x)&(y)) | ((x)&(z)) | ((y)&(z)))
#define GG0(x,y,z) ((x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x)&(y)) | ((~(x))&(z)))
#define P0(x) ((x) ^ ROTL((x),9) ^ ROTL((x),17))
#define P1(x) ((x) ^ ROTL((x),15) ^ ROTL((x),23))

static const uint32_t T[64] = {
    0x79CC4519,0xF3988A32,0xE7311465,0xCE6228CB,
    0x9CC45197,0x3988A32F,0x7311465E,0xE6228CBC,
    0xCC451979,0x988A32F3,0x311465E7,0x6228CBCE,
    0xC451979C,0x88A32F39,0x11465E73,0x228CBCE6,
    0x451979CC,0x8A32F398,0x1465E731,0x28CBCE62,
    0x51979CC4,0xA32F3988,0x465E7311,0x8CBCE622,
    0x1979CC45,0x32F3988A,0x65E73114,0xCBCE6228,
    0x979CC451,0x2F3988A3,0x5E731146,0xBCE6228C,
    0x79CC4519,0xF3988A32,0xE7311465,0xCE6228CB,
    0x9CC45197,0x3988A32F,0x7311465E,0xE6228CBC,
    0xCC451979,0x988A32F3,0x311465E7,0x6228CBCE,
    0xC451979C,0x88A32F39,0x11465E73,0x228CBCE6,
    0x451979CC,0x8A32F398,0x1465E731,0x28CBCE62,
    0x51979CC4,0xA32F3988,0x465E7311,0x8CBCE622,
    0x1979CC45,0x32F3988A,0x65E73114,0xCBCE6228
};

// SM3 压缩函数
void sm3_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68], W1[64];
    uint32_t A,B,C,D,E,F,G,H,SS1,SS2,TT1,TT2;

    // 消息扩展
    for(int i=0;i<16;i++)
        W[i] = ((uint32_t)block[i*4]<<24) | ((uint32_t)block[i*4+1]<<16) |
               ((uint32_t)block[i*4+2]<<8) | ((uint32_t)block[i*4+3]);
    
    for(int i=16;i<68;i++)
        W[i] = P1(W[i-16]^W[i-9]^ROTL(W[i-3],15))^ROTL(W[i-13],7)^W[i-6];
    
    for(int i=0;i<64;i++)
        W1[i] = W[i]^W[i+4];

    // 压缩
    A=state[0]; B=state[1]; C=state[2]; D=state[3];
    E=state[4]; F=state[5]; G=state[6]; H=state[7];
    
    for(int j=0;j<64;j++){
        SS1=ROTL((ROTL(A,12)+E+ROTL(T[j],j)),7);
        SS2=SS1^ROTL(A,12);
        TT1 = (j<16) ? (FF0(A,B,C)+D+SS2+W1[j]) : (FF1(A,B,C)+D+SS2+W1[j]);
        TT2 = (j<16) ? (GG0(E,F,G)+H+SS1+W[j]) : (GG1(E,F,G)+H+SS1+W[j]);
        
        D=C; C=ROTL(B,9); B=A; A=TT1;
        H=G; G=ROTL(F,19); F=E; E=P0(TT2);
    }
    
    state[0]^=A; state[1]^=B; state[2]^=C; state[3]^=D;
    state[4]^=E; state[5]^=F; state[6]^=G; state[7]^=H;
}

// 初始化SM3上下文
typedef struct {
    uint32_t state[8];
    uint64_t count; // 处理的总字节数
    uint8_t buffer[64]; // 缓冲区
} SM3_CTX;

void sm3_init(SM3_CTX *ctx) {
    ctx->state[0] = 0x7380166F;
    ctx->state[1] = 0x4914B2B9;
    ctx->state[2] = 0x172442D7;
    ctx->state[3] = 0xDA8A0600;
    ctx->state[4] = 0xA96F30BC;
    ctx->state[5] = 0x163138AA;
    ctx->state[6] = 0xE38DEE4D;
    ctx->state[7] = 0xB0FB0E4E;
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

// 更新SM3上下文
void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t len) {
    size_t fill, left = ctx->count % 64;
    ctx->count += len;
    
    if(left) {
        fill = 64 - left;
        if(len < fill) {
            memcpy(ctx->buffer + left, data, len);
            return;
        }
        memcpy(ctx->buffer + left, data, fill);
        sm3_compress(ctx->state, ctx->buffer);
        data += fill;
        len -= fill;
        left = 0;
    }
    
    while(len >= 64) {
        sm3_compress(ctx->state, data);
        data += 64;
        len -= 64;
    }
    
    if(len > 0)
        memcpy(ctx->buffer + left, data, len);
}

// 完成哈希计算
void sm3_final(SM3_CTX *ctx, uint8_t digest[32]) {
    uint8_t msglen[8];
    uint64_t bit_len = ctx->count * 8;
    
    // 填充消息
    uint8_t pad = 0x80;
    sm3_update(ctx, &pad, 1);
    
    // 添加填充0，直到 (count % 64) == 56
    pad = 0;
    while((ctx->count % 64) != 56)
        sm3_update(ctx, &pad, 1);
    
    // 添加消息长度（大端）
    for(int i=0;i<8;i++)
        msglen[i] = (bit_len >> (56 - i*8)) & 0xFF;
    sm3_update(ctx, msglen, 8);
    
    // 输出哈希值
    for(int i=0;i<8;i++) {
        digest[i*4]   = (ctx->state[i] >> 24) & 0xFF;
        digest[i*4+1] = (ctx->state[i] >> 16) & 0xFF;
        digest[i*4+2] = (ctx->state[i] >> 8) & 0xFF;
        digest[i*4+3] = ctx->state[i] & 0xFF;
    }
}

// 计算 SM3 对于原始长度 original_len 会产生的「填充字节」（包含 0x80、若干 0x00 以及 8 字节长度）
// 返回分配的缓冲区（调用者负责 free）和总字节数 pad_len
uint8_t* sm3_make_padding(uint64_t original_len, size_t *pad_len_out) {
    // 先计算 1 + k 使得 (original_len + 1 + k) % 64 == 56
    size_t rem = (size_t)(original_len % 64);
    size_t pad_len_without_len;
    if (rem < 56) {
        pad_len_without_len = 56 - rem;
    } else {
        pad_len_without_len = 56 + (64 - rem);
    }
    // pad_len_without_len >=1 (包含 0x80)
    size_t total_pad = pad_len_without_len + 8; // 加上 8 字节长度
    uint8_t *pad = (uint8_t*)malloc(total_pad);
    if(!pad) return NULL;
    memset(pad, 0, total_pad);
    pad[0] = 0x80;
    uint64_t bit_len = original_len * 8;
    // 将 bit_len 放在最后 8 字节（大端）
    for(int i=0;i<8;i++) {
        pad[pad_len_without_len + i] = (bit_len >> (56 - 8*i)) & 0xFF;
    }
    if(pad_len_out) *pad_len_out = total_pad;
    return pad;
}

// 长度扩展攻击函数（修正）：
// 从 original_hash 恢复内部状态，然后把 ctx.count 设为 original_len + 原始填充长度，
// 再喂入 extension，最后 sm3_final 得到伪造哈希。
void length_extension_attack(
    const uint8_t original_hash[32],
    uint64_t original_length, // 原始消息的字节长度
    const uint8_t *extension,
    size_t extension_len,
    uint8_t forged_hash[32])
{
    SM3_CTX ctx;
    
    // 从原始哈希恢复 state（大端）
    for(int i=0;i<8;i++)
        ctx.state[i] = ((uint32_t)original_hash[i*4]<<24) | ((uint32_t)original_hash[i*4+1]<<16) |
                       ((uint32_t)original_hash[i*4+2]<<8) | ((uint32_t)original_hash[i*4+3]);
    // buffer 内容 irrelevant for continuing compression (we assume message boundary is at block boundary after original padding)
    memset(ctx.buffer, 0, sizeof(ctx.buffer));
    
    // 计算原始消息会产生的填充长度
    size_t orig_pad_len = 0;
    uint8_t *orig_pad = sm3_make_padding(original_length, &orig_pad_len);
    if(!orig_pad) {
        fprintf(stderr, "malloc failed\n");
        exit(1);
    }
    // 将 ctx.count 设为原始消息已经被 SM3 处理过的字节数（原始消息 + 原始填充）
    ctx.count = original_length + orig_pad_len;
    
    // 现在只把扩展的数据作为 "新数据" 处理
    sm3_update(&ctx, extension, extension_len);
    
    // 最后进行常规的 sm3_final（它会追加 padding 和新的长度 —— 新长度基于 ctx.count）
    sm3_final(&ctx, forged_hash);
    
    free(orig_pad);
}

// 辅助：直接计算完整消息（secret || message || padding || extension）的哈希（用于验证）
void compute_direct_hash(
    const uint8_t *full_msg, size_t full_msg_len,
    uint8_t out_hash[32])
{
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, full_msg, full_msg_len);
    sm3_final(&ctx, out_hash);
}

// 打印 hex
void print_hex(const uint8_t *d, size_t n) {
    for(size_t i=0;i<n;i++) printf("%02x", d[i]);
    printf("\n");
}

// 主测试
int main() {
    const uint8_t secret[] = "secret";
    const uint8_t message[] = "data";
    const uint8_t extension[] = ";admin=1";
    uint64_t original_length = sizeof(secret)-1 + sizeof(message)-1; // secret||message 的字节长度

    // 1. 计算原始哈希 H(secret || message)
    uint8_t original_hash[32];
    {
        SM3_CTX ctx;
        sm3_init(&ctx);
        sm3_update(&ctx, secret, sizeof(secret)-1);
        sm3_update(&ctx, message, sizeof(message)-1);
        sm3_final(&ctx, original_hash);
    }

    printf("Original hash: ");
    print_hex(original_hash, 32);

    // 2. 用长度扩展攻击伪造哈希
    uint8_t forged_hash[32];
    length_extension_attack(original_hash, original_length, extension, sizeof(extension)-1, forged_hash);

    printf("Forged hash  : ");
    print_hex(forged_hash, 32);

    // 3. 为验证，构造完整字节串： secret || message || original_padding || extension
    size_t orig_pad_len = 0;
    uint8_t *orig_pad = sm3_make_padding(original_length, &orig_pad_len);
    if(!orig_pad) { fprintf(stderr, "malloc failed\n"); return 1; }

    size_t full_len = original_length + orig_pad_len + (sizeof(extension)-1);
    uint8_t *full_msg = (uint8_t*)malloc(full_len);
    if(!full_msg) { fprintf(stderr, "malloc failed\n"); free(orig_pad); return 1; }

    // 填充 full_msg： secret + message + padding + extension
    memcpy(full_msg, secret, sizeof(secret)-1);
    memcpy(full_msg + (sizeof(secret)-1), message, sizeof(message)-1);
    memcpy(full_msg + original_length, orig_pad, orig_pad_len);
    memcpy(full_msg + original_length + orig_pad_len, extension, sizeof(extension)-1);

    // 4. 直接计算完整消息哈希
    uint8_t direct_hash[32];
    compute_direct_hash(full_msg, full_len, direct_hash);

    printf("Direct hash  : ");
    print_hex(direct_hash, 32);

    // 比较
    if(memcmp(forged_hash, direct_hash, 32) == 0) {
        printf("\nSuccess! Length extension attack worked.\n");
    } else {
        printf("\nAttack failed. Hashes don't match.\n");
    }

    free(orig_pad);
    free(full_msg);
    return 0;
}

