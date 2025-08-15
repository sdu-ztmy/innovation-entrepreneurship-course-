
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>



#define ROTL(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define FF0(x,y,z) ((x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x)&(y)) | ((x)&(z)) | ((y)&(z)))
#define GG0(x,y,z) ((x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x)&(y)) | ((~(x))&(z)))
#define P0(x) ((x) ^ ROTL((x),9) ^ ROTL((x),17))
#define P1(x) ((x) ^ ROTL((x),15) ^ ROTL((x),23))

static const uint32_t TSM3[64] = {
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

typedef struct {
    uint32_t state[8];
    uint64_t count; // processed bytes
    uint8_t buffer[64];
} SM3_CTX;

static void sm3_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68], W1[64];
    uint32_t A,B,C,D,E,F,G,H,SS1,SS2,TT1,TT2;
    for(int i=0;i<16;i++)
        W[i] = ((uint32_t)block[i*4]<<24) | ((uint32_t)block[i*4+1]<<16) |
               ((uint32_t)block[i*4+2]<<8) | ((uint32_t)block[i*4+3]);
    for(int i=16;i<68;i++)
        W[i] = P1(W[i-16]^W[i-9]^ROTL(W[i-3],15)) ^ ROTL(W[i-13],7) ^ W[i-6];
    for(int i=0;i<64;i++) W1[i] = W[i] ^ W[i+4];

    A=state[0]; B=state[1]; C=state[2]; D=state[3];
    E=state[4]; F=state[5]; G=state[6]; H=state[7];
    for(int j=0;j<64;j++){
        SS1 = ROTL((ROTL(A,12) + E + ROTL(TSM3[j], j)), 7);
        SS2 = SS1 ^ ROTL(A,12);
        if(j<16) {
            TT1 = FF0(A,B,C) + D + SS2 + W1[j];
            TT2 = GG0(E,F,G) + H + SS1 + W[j];
        } else {
            TT1 = FF1(A,B,C) + D + SS2 + W1[j];
            TT2 = GG1(E,F,G) + H + SS1 + W[j];
        }
        D=C; C=ROTL(B,9); B=A; A=TT1;
        H=G; G=ROTL(F,19); F=E; E=P0(TT2);
    }
    state[0]^=A; state[1]^=B; state[2]^=C; state[3]^=D;
    state[4]^=E; state[5]^=F; state[6]^=G; state[7]^=H;
}

static void sm3_init(SM3_CTX *ctx) {
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

static void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t len) {
    size_t left = ctx->count % 64;
    ctx->count += len;
    if(left) {
        size_t need = 64 - left;
        if(len < need) {
            memcpy(ctx->buffer + left, data, len);
            return;
        }
        memcpy(ctx->buffer + left, data, need);
        sm3_compress(ctx->state, ctx->buffer);
        data += need;
        len -= need;
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

static void sm3_final(SM3_CTX *ctx, uint8_t digest[32]) {
    uint8_t pad = 0x80;
    sm3_update(ctx, &pad, 1);
    pad = 0x00;
    while((ctx->count % 64) != 56) sm3_update(ctx, &pad, 1);
    uint64_t bit_len = ctx->count * 8;
    uint8_t lenbuf[8];
    for(int i=0;i<8;i++) lenbuf[i] = (bit_len >> (56 - 8*i)) & 0xFF;
    sm3_update(ctx, lenbuf, 8);
    for(int i=0;i<8;i++){
        digest[i*4]   = (ctx->state[i] >> 24) & 0xFF;
        digest[i*4+1] = (ctx->state[i] >> 16) & 0xFF;
        digest[i*4+2] = (ctx->state[i] >> 8) & 0xFF;
        digest[i*4+3] = ctx->state[i] & 0xFF;
    }
}

/* Convenience wrapper: hash = SM3(in, inlen) */
static void sm3_hash(const uint8_t *in, size_t inlen, uint8_t out[32]) {
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, in, inlen);
    sm3_final(&ctx, out);
}


#define HASH_LEN 32
typedef struct {
    uint8_t h[HASH_LEN];
} Hash;

static void print_hex(const uint8_t *d, size_t n) {
    for(size_t i=0;i<n;i++) printf("%02x", d[i]);
}

/* Hash leaf: Hash(0x00 || leaf_data) */
static void hash_leaf(const uint8_t *data, size_t datalen, uint8_t out[HASH_LEN]) {
    uint8_t *buf = (uint8_t*)malloc(datalen + 1);
    buf[0] = 0x00;
    memcpy(buf+1, data, datalen);
    sm3_hash(buf, datalen+1, out);
    free(buf);
}

static void hash_node(const uint8_t left[HASH_LEN], const uint8_t right[HASH_LEN], uint8_t out[HASH_LEN]) {
    uint8_t buf[1 + HASH_LEN + HASH_LEN];
    buf[0] = 0x01;
    memcpy(buf+1, left, HASH_LEN);
    memcpy(buf+1+HASH_LEN, right, HASH_LEN);
    sm3_hash(buf, 1 + HASH_LEN + HASH_LEN, out);
}

static int lexcmp(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) {
    size_t minlen = alen < blen ? alen : blen;
    int r = memcmp(a, b, minlen);
    if(r != 0) return r;
    if(alen < blen) return -1;
    if(alen > blen) return 1;
    return 0;
}


typedef struct {
    /* Each level is an array of Hash, level 0 is leaves, level L is root level (size 1) */
    Hash **levels;   // pointers to arrays
    size_t *level_sizes;
    int level_count;
} MerkleTree;

static void merkle_free(MerkleTree *mt) {
    if(!mt) return;
    for(int i=0;i<mt->level_count;i++){
        free(mt->levels[i]);
    }
    free(mt->levels);
    free(mt->level_sizes);
    free(mt);
}


typedef struct {
    uint8_t *data;
    size_t len;
} Leaf;

static MerkleTree *merkle_build_sorted(Leaf *leaves, size_t nleaves) {
    if(nleaves == 0) return NULL;

    qsort(leaves, nleaves, sizeof(Leaf), (int(*)(const void*,const void*)) ( +[](const Leaf *a, const Leaf *b)->int {
        size_t minlen = a->len < b->len ? a->len : b->len;
        int r = memcmp(a->data, b->data, minlen);
        if(r != 0) return r;
        if(a->len < b->len) return -1;
        if(a->len > b->len) return 1;
        return 0;
    }));

    int lvl = 0;
    size_t tmp = nleaves;
    while(tmp > 1) { tmp = (tmp + 1) / 2; lvl++; }
    int level_count = lvl + 1;

    MerkleTree *mt = (MerkleTree*)malloc(sizeof(MerkleTree));
    mt->levels = (Hash**)calloc(level_count, sizeof(Hash*));
    mt->level_sizes = (size_t*)calloc(level_count, sizeof(size_t));
    mt->level_count = level_count;


    mt->level_sizes[0] = nleaves;
    mt->levels[0] = (Hash*)malloc(sizeof(Hash) * mt->level_sizes[0]);
    for(size_t i=0;i<nleaves;i++){
        hash_leaf(leaves[i].data, leaves[i].len, mt->levels[0][i].h);
    }


    for(int L=1; L<level_count; L++){
        size_t prev_size = mt->level_sizes[L-1];
        size_t cur_size = (prev_size + 1) / 2;
        mt->level_sizes[L] = cur_size;
        mt->levels[L] = (Hash*)malloc(sizeof(Hash) * cur_size);
        for(size_t i=0;i<cur_size;i++){
            size_t left_idx = i*2;
            size_t right_idx = i*2 + 1;
            const uint8_t *left = mt->levels[L-1][left_idx].h;
            const uint8_t *right;
            uint8_t tmp_right[HASH_LEN];
            if(right_idx < prev_size) {
                right = mt->levels[L-1][right_idx].h;
            } else {
                // duplicate left if no right sibling
                right = left;
            }
            hash_node(left, right, mt->levels[L][i].h);
        }
    }

    return mt;
}


static void merkle_root(const MerkleTree *mt, uint8_t out[HASH_LEN]) {
    if(!mt) return;
    Hash *root = mt->levels[mt->level_count - 1];
    memcpy(out, root[0].h, HASH_LEN);
}


typedef struct {
    uint8_t sibling[HASH_LEN];
    int sibling_is_left;
} ProofElement;

typedef struct {
    ProofElement *elems;
    size_t elem_count;
    size_t leaf_index; // index in sorted leaves
} InclusionProof;

static InclusionProof merkle_inclusion_proof(const MerkleTree *mt, size_t idx) {
    InclusionProof proof;
    proof.elems = NULL;
    proof.elem_count = 0;
    proof.leaf_index = idx;

    if(!mt) return proof;
    if(idx >= mt->level_sizes[0]) return proof;

    int levels_above = mt->level_count - 1;
    proof.elems = (ProofElement*)malloc(sizeof(ProofElement) * levels_above);
    size_t cur_idx = idx;
    size_t count = 0;
    for(int L=0; L<levels_above; L++){
        size_t sibling_idx;
        int sibling_is_left = 0;
        if(cur_idx % 2 == 0) {
            sibling_idx = cur_idx + 1;
            sibling_is_left = 0; // sibling is right
        } else {
            sibling_idx = cur_idx - 1;
            sibling_is_left = 1; // sibling is left
        }
        size_t level_size = mt->level_sizes[L];
        if(sibling_idx >= level_size) {
            // sibling missing -> duplicate cur node; sibling hash equals cur node hash
            memcpy(proof.elems[count].sibling, mt->levels[L][cur_idx].h, HASH_LEN);
            proof.elems[count].sibling_is_left = sibling_is_left;
        } else {
            memcpy(proof.elems[count].sibling, mt->levels[L][sibling_idx].h, HASH_LEN);
            proof.elems[count].sibling_is_left = sibling_is_left;
        }
        count++;
        cur_idx = cur_idx / 2;
    }
    proof.elem_count = count;
    return proof;
}

static void free_inclusion_proof(InclusionProof *p) {
    if(!p) return;
    free(p->elems);
    p->elems = NULL;
    p->elem_count = 0;
}


static int merkle_verify_inclusion(const uint8_t *leaf_data, size_t leaf_len, const InclusionProof *proof, const uint8_t root[HASH_LEN]) {
    uint8_t cur[HASH_LEN];
    hash_leaf(leaf_data, leaf_len, cur);

    // at level 0 index = proof->leaf_index
    size_t idx = proof->leaf_index;
    for(size_t i=0;i<proof->elem_count;i++){
        uint8_t newh[HASH_LEN];
        if(proof->elems[i].sibling_is_left) {
            // sibling is left: hash(node = sibling || cur)
            hash_node(proof->elems[i].sibling, cur, newh);
        } else {
            // sibling is right: hash(node = cur || sibling)
            hash_node(cur, proof->elems[i].sibling, newh);
        }
        memcpy(cur, newh, HASH_LEN);
        idx /= 2;
    }
    return memcmp(cur, root, HASH_LEN) == 0;
}


typedef struct {
    // indices and data for neighbors; elem_count may be 0,1,2
    InclusionProof left_proof;
    const uint8_t *left_data;
    size_t left_len;
    int has_left;

    InclusionProof right_proof;
    const uint8_t *right_data;
    size_t right_len;
    int has_right;
} NonInclusionProof;

static NonInclusionProof merkle_noninclusion_proof(const MerkleTree *mt, Leaf *sorted_leaves, size_t nleaves, const uint8_t *q, size_t qlen) {
    NonInclusionProof np;
    memset(&np, 0, sizeof(np));
    np.has_left = np.has_right = 0;


    size_t lo = 0, hi = nleaves;
    while(lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = lexcmp(sorted_leaves[mid].data, sorted_leaves[mid].len, q, qlen);
        if(cmp < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    size_t ins = lo; // insertion index: q would be placed at 'ins' to maintain order
    if(ins < nleaves && lexcmp(sorted_leaves[ins].data, sorted_leaves[ins].len, q, qlen) == 0) {
        // q exactly equals a leaf -> treat as inclusion (left_proof holds it)
        np.has_left = 1;
        np.left_data = sorted_leaves[ins].data;
        np.left_len = sorted_leaves[ins].len;
        np.left_proof = merkle_inclusion_proof(mt, ins);
        return np;
    }

    if(ins > 0) {
        size_t left_idx = ins - 1;
        np.has_left = 1;
        np.left_data = sorted_leaves[left_idx].data;
        np.left_len = sorted_leaves[left_idx].len;
        np.left_proof = merkle_inclusion_proof(mt, left_idx);
    }
    if(ins < nleaves) {
        size_t right_idx = ins;
        np.has_right = 1;
        np.right_data = sorted_leaves[right_idx].data;
        np.right_len = sorted_leaves[right_idx].len;
        np.right_proof = merkle_inclusion_proof(mt, right_idx);
    }
    return np;
}

static void free_noninclusion_proof(NonInclusionProof *p) {
    if(!p) return;
    if(p->has_left) free_inclusion_proof(&p->left_proof);
    if(p->has_right) free_inclusion_proof(&p->right_proof);
}


static int merkle_verify_noninclusion(const uint8_t *q, size_t qlen, const NonInclusionProof *np, const uint8_t root[HASH_LEN]) {
    if(np->has_left) {
        if(!merkle_verify_inclusion(np->left_data, np->left_len, &np->left_proof, root)) {
            return 0;
        }
    }
    if(np->has_right) {
        if(!merkle_verify_inclusion(np->right_data, np->right_len, &np->right_proof, root)) {
            return 0;
        }
    }
    if(np->has_left && np->has_right) {
        // left < q < right
        if(!(lexcmp(np->left_data, np->left_len, q, qlen) < 0 && lexcmp(q, qlen, np->right_data, np->right_len) < 0)) return 0;
    } else if(np->has_left && !np->has_right) {
        // q > left
        if(!(lexcmp(np->left_data, np->left_len, q, qlen) < 0)) return 0;
    } else if(!np->has_left && np->has_right) {
        // q < right
        if(!(lexcmp(q, qlen, np->right_data, np->right_len) < 0)) return 0;
    } else {
        // no neighbors? means empty tree; q is non-included trivially
        return 1;
    }
    return 1;
}

/* -------------------- Demo & tests -------------------- */

int main() {
    const size_t NLEAVES = 100000; // 10w
    printf("Building Merkle tree with %zu leaves...\n", NLEAVES);

    Leaf *leaves = (Leaf*)malloc(sizeof(Leaf) * NLEAVES);
    if(!leaves) { fprintf(stderr, "malloc leaves failed\n"); return 1; }
    // We'll keep the data allocated so pointers remain valid after sorting
    for(size_t i=0;i<NLEAVES;i++){
        char buf[64];
        int bl = snprintf(buf, sizeof(buf), "leaf-%08zu", i); // fixed width to ensure lexicographic property
        leaves[i].len = (size_t)bl;
        leaves[i].data = (uint8_t*)malloc(leaves[i].len);
        memcpy(leaves[i].data, buf, leaves[i].len);
    }

    MerkleTree *mt = merkle_build_sorted(leaves, NLEAVES);
    if(!mt) { fprintf(stderr, "merkle build failed\n"); return 1; }

    uint8_t root[HASH_LEN];
    merkle_root(mt, root);
    printf("Merkle root: ");
    print_hex(root, HASH_LEN);
    printf("\n");

    const char *exist_sample = "leaf-00000123";
    printf("\n--- Inclusion proof for \"%s\" ---\n", exist_sample);
    size_t lo = 0, hi = NLEAVES;
    size_t found = (size_t)-1;
    while(lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = lexcmp(leaves[mid].data, leaves[mid].len, (const uint8_t*)exist_sample, strlen(exist_sample));
        if(cmp == 0) { found = mid; break; }
        else if(cmp < 0) lo = mid + 1;
        else hi = mid;
    }
    if(found == (size_t)-1) {
        printf("value not found (unexpected)\n");
    } else {
        InclusionProof p = merkle_inclusion_proof(mt, found);
        printf("Inclusion proof length: %zu\n", p.elem_count);
        // verify
        int ok = merkle_verify_inclusion((const uint8_t*)exist_sample, strlen(exist_sample), &p, root);
        printf("Inclusion proof verification: %s\n", ok ? "PASS" : "FAIL");
        free_inclusion_proof(&p);
    }

    const char *nonexist1 = "leaf-99999999"; // bigger than any
    const char *nonexist2 = "leaf-00000005"; // likely exists; but treat as demonstration
    const char *nonexist3 = "leaf-00000XYZ"; // not present
    const char *queries[] = { nonexist1, nonexist3 };
    printf("\n--- Non-inclusion proofs ---\n");
    for(size_t qi=0; qi<2; qi++){
        const char *q = queries[qi];
        printf("Query \"%s\"\n", q);
        NonInclusionProof np = merkle_noninclusion_proof(mt, leaves, NLEAVES, (const uint8_t*)q, strlen(q));
        // print status
        if(np.has_left && np.has_right && (np.left_data!=NULL) && (np.right_data!=NULL)) {
            printf("neighbors: left=\"%.*s\", right=\"%.*s\"\n",
                   (int)np.left_len, (char*)np.left_data, (int)np.right_len, (char*)np.right_data);
        } else if(np.has_left) {
            printf("only left neighbor: \"%.*s\"\n", (int)np.left_len, (char*)np.left_data);
        } else if(np.has_right) {
            printf("only right neighbor: \"%.*s\"\n", (int)np.right_len, (char*)np.right_data);
        } else {
            printf("tree empty\n");
        }
        int ok = merkle_verify_noninclusion((const uint8_t*)q, strlen(q), &np, root);
        printf("Non-inclusion verification: %s\n", ok ? "PASS" : "FAIL");
        free_noninclusion_proof(&np);
    }

    merkle_free(mt);
    for(size_t i=0;i<NLEAVES;i++) free(leaves[i].data);
    free(leaves);

    printf("Done.\n");
    return 0;
}

