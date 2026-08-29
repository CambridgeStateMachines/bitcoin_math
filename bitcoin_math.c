/*
 * Copyright (c) 2025, 2026 Cambridge State Machines
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies
 * or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * The code for the SHA256, SHA512, HMAC-SHA256 and HMAC-SHA512 functions
 * in this file was adapted from Olivier Gay's implementation of SHA2 in
 * C (https://github.com/ogay), licensed under the BSD license.
 *
 * Copyright (C) 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define _CRT_RAND_S // prerequisite for the (cryptographically secure) rand_s function, part of the Windows stdlib

#include <ctype.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* HASH FUNCTIONS RIPEMD160 */

uint32_t rol(uint32_t, uint8_t);
void ripemd160_compute_line(uint32_t *, uint32_t *, uint32_t *, uint8_t *, uint8_t *, uint32_t *, uint8_t *);
void ripemd160_update_digest(uint32_t *, uint32_t *);
void ripemd160(const uint8_t *, uint32_t, uint8_t *);

uint32_t ripemd160_initial_digest[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

uint8_t ripemd160_rho[16] = { 0x7, 0x4, 0xd, 0x1, 0xa, 0x6, 0xf, 0x3, 0xc, 0x0, 0x9, 0x5, 0x2, 0xe, 0xb, 0x8 };

uint8_t ripemd160_shifts[80] = { 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7, 13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9, 14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6, 15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5 };

uint32_t ripemd160_constants_left[5] = { 0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e };

uint32_t ripemd160_constants_right[5] = { 0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000 };

uint8_t ripemd160_fns_left[5]  = { 1, 2, 3, 4, 5 };

uint8_t ripemd160_fns_right[5] = { 5, 4, 3, 2, 1 };

uint32_t rol(uint32_t x, uint8_t n)
{
    return (((x) << (n)) | ((x) >> (32 - (n))));
}

void ripemd160_compute_line(uint32_t* digest, uint32_t* words, uint32_t* chunk, uint8_t* index, uint8_t* shifts, uint32_t* ks, uint8_t* fns)
{
    for (uint8_t i = 0; i < 5; i++) {
        words[i] = digest[i];
    }

    for (uint8_t round = 0; /* breaks out mid-loop */; round++) {
        uint32_t k  = ks[round];
        uint8_t  fn = fns[round];
        for (uint8_t i = 0; i < 16; i++) {
            uint32_t tmp;
            switch (fn) {
                case 1:
                    tmp = words[1] ^ words[2] ^ words[3];
                    break;
                case 2:
                    tmp = (words[1] & words[2]) | (~words[1] & words[3]);
                    break;
                case 3:
                    tmp = (words[1] | ~words[2]) ^ words[3];
                    break;
                case 4:
                    tmp = (words[1] & words[3]) | (words[2] & ~words[3]);
                    break;
                case 5:
                    tmp = words[1] ^ (words[2] | ~words[3]);
                    break;
            }
            tmp += words[0] + chunk[index[i]] + k;
            tmp = rol(tmp, shifts[index[i]]) + words[4];
            words[0] = words[4];
            words[4] = words[3];
            words[3] = rol(words[2], 10);
            words[2] = words[1];
            words[1] = tmp;
        }
        if (round == 4) {
            break;
        }
        shifts += 16;

        uint8_t index_tmp[16];
        for (uint8_t i = 0; i < 16; i++) {
            index_tmp[i] = ripemd160_rho[index[i]];
        }
        for (uint8_t i = 0; i < 16; i++) {
            index[i] = index_tmp[i];
        }
    }
}

void ripemd160_update_digest(uint32_t* digest, uint32_t* chunk)
{
    uint8_t index[16];

    /* initial permutation for left line is the identity */
    for (uint8_t i = 0; i < 16; i++) {
        index[i] = i;
    }
    uint32_t words_left[5];
    ripemd160_compute_line(digest, words_left, chunk, index, ripemd160_shifts, ripemd160_constants_left, ripemd160_fns_left);

    /* initial permutation for right line is 5+9i (mod 16) */
    index[0] = 5;
    for (uint8_t i = 1; i < 16; i++) {
        index[i] = (index[i-1] + 9) & 0x0f;
    }
    uint32_t words_right[5];
    ripemd160_compute_line(digest, words_right, chunk, index, ripemd160_shifts, ripemd160_constants_right, ripemd160_fns_right);

    /* update digest */
    digest[0] += words_left[1] + words_right[2];
    digest[1] += words_left[2] + words_right[3];
    digest[2] += words_left[3] + words_right[4];
    digest[3] += words_left[4] + words_right[0];
    digest[4] += words_left[0] + words_right[1];

    /* final rotation */
    words_left[0] = digest[0];
    digest[0] = digest[1];
    digest[1] = digest[2];
    digest[2] = digest[3];
    digest[3] = digest[4];
    digest[4] = words_left[0];
}

void ripemd160(const uint8_t* data, uint32_t data_len, uint8_t* digest_bytes)
{
    /* NB assumes correct endianness */
    uint32_t *digest = (uint32_t*)digest_bytes;
    for (uint8_t i = 0; i < 5; i++) {
        digest[i] = ripemd160_initial_digest[i];
    }

    const uint8_t *last_chunk_start = data + (data_len & (~0x3f));
    while (data < last_chunk_start) {
        ripemd160_update_digest(digest, (uint32_t*)data);
        data += 0x40;
    }

    uint8_t last_chunk[0x40];
    uint8_t leftover_size = data_len & 0x3f;
    for (uint8_t i = 0; i < leftover_size; i++) {
        last_chunk[i] = *data++;
    }

    /* append a single 1 bit and then zeroes, leaving 8 bytes for the length at the end */
    last_chunk[leftover_size] = 0x80;
    for (uint8_t i = leftover_size + 1; i < 0x40; i++) {
        last_chunk[i] = 0;
    }

    if (leftover_size >= 0x38) {
        /* no room for size in this chunk, add another chunk of zeroes */
        ripemd160_update_digest(digest, (uint32_t*)last_chunk);
        for (uint8_t i = 0; i < 0x38; i++) {
            last_chunk[i] = 0;
        }
    }

    uint32_t *length_lsw = (uint32_t *)(last_chunk + 0x38);
    *length_lsw = (data_len << 3);
    uint32_t *length_msw = (uint32_t *)(last_chunk + 0x3c);
    *length_msw = (data_len >> 29);

    ripemd160_update_digest(digest, (uint32_t*)last_chunk);
}

/* HASH FUNCTIONS SHA256 AND SHA512 */

#define SHA256_DIGEST_SIZE ( 256 / 8)
#define SHA512_DIGEST_SIZE ( 512 / 8)

#define SHA256_BLOCK_SIZE  ( 512 / 8)
#define SHA512_BLOCK_SIZE  (1024 / 8)

typedef struct {
    uint64_t tot_len;
    uint64_t len;
    uint8_t block[2 * SHA256_BLOCK_SIZE];
    uint32_t h[8];
} sha256_ctx;

typedef struct {
    uint64_t tot_len;
    uint64_t len;
    uint8_t block[2 * SHA512_BLOCK_SIZE];
    uint64_t h[8];
} sha512_ctx;

void sha256_init(sha256_ctx * ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *message, uint64_t len);
void sha256_final(sha256_ctx *ctx, uint8_t *digest);
void sha256(const uint8_t *message, uint64_t len, uint8_t *digest);

void sha512_init(sha512_ctx *ctx);
void sha512_update(sha512_ctx *ctx, const uint8_t *message, uint64_t len);
void sha512_final(sha512_ctx *ctx, uint8_t *digest);
void sha512(const uint8_t *message, uint64_t len, uint8_t *digest);

#define SHFR(x, n)    (x >> n)
#define ROTR(x, n)   ((x >> n) | (x << ((sizeof (x) << 3) - n)))
#define ROTL(x, n)   ((x << n) | (x >> ((sizeof (x) << 3) - n)))
#define CH(x, y, z)  ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define SHA256_F1(x) (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SHA256_F2(x) (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SHA256_F3(x) (ROTR(x,  7) ^ ROTR(x, 18) ^ SHFR(x,  3))
#define SHA256_F4(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHFR(x, 10))

#define SHA512_F1(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define SHA512_F2(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define SHA512_F3(x) (ROTR(x,  1) ^ ROTR(x,  8) ^ SHFR(x,  7))
#define SHA512_F4(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHFR(x,  6))

#define UNPACK32(x, str)                      \
{                                             \
    *((str) + 3) = (uint8_t) ((x)      );       \
    *((str) + 2) = (uint8_t) ((x) >>  8);       \
    *((str) + 1) = (uint8_t) ((x) >> 16);       \
    *((str) + 0) = (uint8_t) ((x) >> 24);       \
}

#define PACK32(str, x)                        \
{                                             \
    *(x) =   ((uint32_t) *((str) + 3)      )    \
           | ((uint32_t) *((str) + 2) <<  8)    \
           | ((uint32_t) *((str) + 1) << 16)    \
           | ((uint32_t) *((str) + 0) << 24);   \
}

#define UNPACK64(x, str)                      \
{                                             \
    *((str) + 7) = (uint8_t) ((x)      );       \
    *((str) + 6) = (uint8_t) ((x) >>  8);       \
    *((str) + 5) = (uint8_t) ((x) >> 16);       \
    *((str) + 4) = (uint8_t) ((x) >> 24);       \
    *((str) + 3) = (uint8_t) ((x) >> 32);       \
    *((str) + 2) = (uint8_t) ((x) >> 40);       \
    *((str) + 1) = (uint8_t) ((x) >> 48);       \
    *((str) + 0) = (uint8_t) ((x) >> 56);       \
}

#define PACK64(str, x)                        \
{                                             \
    *(x) =   ((uint64_t) *((str) + 7)      )    \
           | ((uint64_t) *((str) + 6) <<  8)    \
           | ((uint64_t) *((str) + 5) << 16)    \
           | ((uint64_t) *((str) + 4) << 24)    \
           | ((uint64_t) *((str) + 3) << 32)    \
           | ((uint64_t) *((str) + 2) << 40)    \
           | ((uint64_t) *((str) + 1) << 48)    \
           | ((uint64_t) *((str) + 0) << 56);   \
}

/* Macros used for loops unrolling */

#define SHA256_SCR(i)                         \
{                                             \
    w[i] =  SHA256_F4(w[i -  2]) + w[i -  7]  \
          + SHA256_F3(w[i - 15]) + w[i - 16]; \
}

#define SHA512_SCR(i)                         \
{                                             \
    w[i] =  SHA512_F4(w[i -  2]) + w[i -  7]  \
          + SHA512_F3(w[i - 15]) + w[i - 16]; \
}

#define SHA256_EXP(a, b, c, d, e, f, g, h, j)               \
{                                                           \
    t1 = wv[h] + SHA256_F2(wv[e]) + CH(wv[e], wv[f], wv[g]) \
         + sha256_k[j] + w[j];                              \
    t2 = SHA256_F1(wv[a]) + MAJ(wv[a], wv[b], wv[c]);       \
    wv[d] += t1;                                            \
    wv[h] = t1 + t2;                                        \
}

#define SHA512_EXP(a, b, c, d, e, f, g ,h, j)               \
{                                                           \
    t1 = wv[h] + SHA512_F2(wv[e]) + CH(wv[e], wv[f], wv[g]) \
         + sha512_k[j] + w[j];                              \
    t2 = SHA512_F1(wv[a]) + MAJ(wv[a], wv[b], wv[c]);       \
    wv[d] += t1;                                            \
    wv[h] = t1 + t2;                                        \
}

static const uint32_t sha256_h0[8] =
            {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

static const uint64_t sha512_h0[8] =
            {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
             0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
             0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
             0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

static const uint32_t sha256_k[64] =
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static const uint64_t sha512_k[80] =
            {0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
             0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
             0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
             0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
             0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
             0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
             0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
             0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
             0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
             0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
             0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
             0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
             0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
             0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
             0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
             0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
             0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
             0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
             0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
             0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
             0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
             0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
             0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
             0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
             0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
             0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
             0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
             0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
             0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
             0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
             0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
             0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
             0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
             0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
             0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
             0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
             0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
             0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
             0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
             0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

/* SHA-2 internal function */

static void sha256_transf(sha256_ctx *ctx, const uint8_t *message, uint64_t block_nb)
{
    uint32_t w[64];
    uint32_t wv[8];
    uint32_t t1, t2;
    const uint8_t *sub_block;
    uint64_t i;

    for (i = 0; i < block_nb; i++) {
        sub_block = message + (i << 6);

        PACK32(&sub_block[ 0], &w[ 0]); PACK32(&sub_block[ 4], &w[ 1]);
        PACK32(&sub_block[ 8], &w[ 2]); PACK32(&sub_block[12], &w[ 3]);
        PACK32(&sub_block[16], &w[ 4]); PACK32(&sub_block[20], &w[ 5]);
        PACK32(&sub_block[24], &w[ 6]); PACK32(&sub_block[28], &w[ 7]);
        PACK32(&sub_block[32], &w[ 8]); PACK32(&sub_block[36], &w[ 9]);
        PACK32(&sub_block[40], &w[10]); PACK32(&sub_block[44], &w[11]);
        PACK32(&sub_block[48], &w[12]); PACK32(&sub_block[52], &w[13]);
        PACK32(&sub_block[56], &w[14]); PACK32(&sub_block[60], &w[15]);

        SHA256_SCR(16); SHA256_SCR(17); SHA256_SCR(18); SHA256_SCR(19);
        SHA256_SCR(20); SHA256_SCR(21); SHA256_SCR(22); SHA256_SCR(23);
        SHA256_SCR(24); SHA256_SCR(25); SHA256_SCR(26); SHA256_SCR(27);
        SHA256_SCR(28); SHA256_SCR(29); SHA256_SCR(30); SHA256_SCR(31);
        SHA256_SCR(32); SHA256_SCR(33); SHA256_SCR(34); SHA256_SCR(35);
        SHA256_SCR(36); SHA256_SCR(37); SHA256_SCR(38); SHA256_SCR(39);
        SHA256_SCR(40); SHA256_SCR(41); SHA256_SCR(42); SHA256_SCR(43);
        SHA256_SCR(44); SHA256_SCR(45); SHA256_SCR(46); SHA256_SCR(47);
        SHA256_SCR(48); SHA256_SCR(49); SHA256_SCR(50); SHA256_SCR(51);
        SHA256_SCR(52); SHA256_SCR(53); SHA256_SCR(54); SHA256_SCR(55);
        SHA256_SCR(56); SHA256_SCR(57); SHA256_SCR(58); SHA256_SCR(59);
        SHA256_SCR(60); SHA256_SCR(61); SHA256_SCR(62); SHA256_SCR(63);

        wv[0] = ctx->h[0]; wv[1] = ctx->h[1];
        wv[2] = ctx->h[2]; wv[3] = ctx->h[3];
        wv[4] = ctx->h[4]; wv[5] = ctx->h[5];
        wv[6] = ctx->h[6]; wv[7] = ctx->h[7];

        SHA256_EXP(0,1,2,3,4,5,6,7, 0); SHA256_EXP(7,0,1,2,3,4,5,6, 1);
        SHA256_EXP(6,7,0,1,2,3,4,5, 2); SHA256_EXP(5,6,7,0,1,2,3,4, 3);
        SHA256_EXP(4,5,6,7,0,1,2,3, 4); SHA256_EXP(3,4,5,6,7,0,1,2, 5);
        SHA256_EXP(2,3,4,5,6,7,0,1, 6); SHA256_EXP(1,2,3,4,5,6,7,0, 7);
        SHA256_EXP(0,1,2,3,4,5,6,7, 8); SHA256_EXP(7,0,1,2,3,4,5,6, 9);
        SHA256_EXP(6,7,0,1,2,3,4,5,10); SHA256_EXP(5,6,7,0,1,2,3,4,11);
        SHA256_EXP(4,5,6,7,0,1,2,3,12); SHA256_EXP(3,4,5,6,7,0,1,2,13);
        SHA256_EXP(2,3,4,5,6,7,0,1,14); SHA256_EXP(1,2,3,4,5,6,7,0,15);
        SHA256_EXP(0,1,2,3,4,5,6,7,16); SHA256_EXP(7,0,1,2,3,4,5,6,17);
        SHA256_EXP(6,7,0,1,2,3,4,5,18); SHA256_EXP(5,6,7,0,1,2,3,4,19);
        SHA256_EXP(4,5,6,7,0,1,2,3,20); SHA256_EXP(3,4,5,6,7,0,1,2,21);
        SHA256_EXP(2,3,4,5,6,7,0,1,22); SHA256_EXP(1,2,3,4,5,6,7,0,23);
        SHA256_EXP(0,1,2,3,4,5,6,7,24); SHA256_EXP(7,0,1,2,3,4,5,6,25);
        SHA256_EXP(6,7,0,1,2,3,4,5,26); SHA256_EXP(5,6,7,0,1,2,3,4,27);
        SHA256_EXP(4,5,6,7,0,1,2,3,28); SHA256_EXP(3,4,5,6,7,0,1,2,29);
        SHA256_EXP(2,3,4,5,6,7,0,1,30); SHA256_EXP(1,2,3,4,5,6,7,0,31);
        SHA256_EXP(0,1,2,3,4,5,6,7,32); SHA256_EXP(7,0,1,2,3,4,5,6,33);
        SHA256_EXP(6,7,0,1,2,3,4,5,34); SHA256_EXP(5,6,7,0,1,2,3,4,35);
        SHA256_EXP(4,5,6,7,0,1,2,3,36); SHA256_EXP(3,4,5,6,7,0,1,2,37);
        SHA256_EXP(2,3,4,5,6,7,0,1,38); SHA256_EXP(1,2,3,4,5,6,7,0,39);
        SHA256_EXP(0,1,2,3,4,5,6,7,40); SHA256_EXP(7,0,1,2,3,4,5,6,41);
        SHA256_EXP(6,7,0,1,2,3,4,5,42); SHA256_EXP(5,6,7,0,1,2,3,4,43);
        SHA256_EXP(4,5,6,7,0,1,2,3,44); SHA256_EXP(3,4,5,6,7,0,1,2,45);
        SHA256_EXP(2,3,4,5,6,7,0,1,46); SHA256_EXP(1,2,3,4,5,6,7,0,47);
        SHA256_EXP(0,1,2,3,4,5,6,7,48); SHA256_EXP(7,0,1,2,3,4,5,6,49);
        SHA256_EXP(6,7,0,1,2,3,4,5,50); SHA256_EXP(5,6,7,0,1,2,3,4,51);
        SHA256_EXP(4,5,6,7,0,1,2,3,52); SHA256_EXP(3,4,5,6,7,0,1,2,53);
        SHA256_EXP(2,3,4,5,6,7,0,1,54); SHA256_EXP(1,2,3,4,5,6,7,0,55);
        SHA256_EXP(0,1,2,3,4,5,6,7,56); SHA256_EXP(7,0,1,2,3,4,5,6,57);
        SHA256_EXP(6,7,0,1,2,3,4,5,58); SHA256_EXP(5,6,7,0,1,2,3,4,59);
        SHA256_EXP(4,5,6,7,0,1,2,3,60); SHA256_EXP(3,4,5,6,7,0,1,2,61);
        SHA256_EXP(2,3,4,5,6,7,0,1,62); SHA256_EXP(1,2,3,4,5,6,7,0,63);

        ctx->h[0] += wv[0]; ctx->h[1] += wv[1];
        ctx->h[2] += wv[2]; ctx->h[3] += wv[3];
        ctx->h[4] += wv[4]; ctx->h[5] += wv[5];
        ctx->h[6] += wv[6]; ctx->h[7] += wv[7];
    }
}

static void sha512_transf(sha512_ctx *ctx, const uint8_t *message, uint64_t block_nb)
{
    uint64_t w[80];
    uint64_t wv[8];
    uint64_t t1, t2;
    const uint8_t *sub_block;
    uint64_t i;
    int j;

    for (i = 0; i < block_nb; i++) {
        sub_block = message + (i << 7);

        PACK64(&sub_block[  0], &w[ 0]); PACK64(&sub_block[  8], &w[ 1]);
        PACK64(&sub_block[ 16], &w[ 2]); PACK64(&sub_block[ 24], &w[ 3]);
        PACK64(&sub_block[ 32], &w[ 4]); PACK64(&sub_block[ 40], &w[ 5]);
        PACK64(&sub_block[ 48], &w[ 6]); PACK64(&sub_block[ 56], &w[ 7]);
        PACK64(&sub_block[ 64], &w[ 8]); PACK64(&sub_block[ 72], &w[ 9]);
        PACK64(&sub_block[ 80], &w[10]); PACK64(&sub_block[ 88], &w[11]);
        PACK64(&sub_block[ 96], &w[12]); PACK64(&sub_block[104], &w[13]);
        PACK64(&sub_block[112], &w[14]); PACK64(&sub_block[120], &w[15]);

        SHA512_SCR(16); SHA512_SCR(17); SHA512_SCR(18); SHA512_SCR(19);
        SHA512_SCR(20); SHA512_SCR(21); SHA512_SCR(22); SHA512_SCR(23);
        SHA512_SCR(24); SHA512_SCR(25); SHA512_SCR(26); SHA512_SCR(27);
        SHA512_SCR(28); SHA512_SCR(29); SHA512_SCR(30); SHA512_SCR(31);
        SHA512_SCR(32); SHA512_SCR(33); SHA512_SCR(34); SHA512_SCR(35);
        SHA512_SCR(36); SHA512_SCR(37); SHA512_SCR(38); SHA512_SCR(39);
        SHA512_SCR(40); SHA512_SCR(41); SHA512_SCR(42); SHA512_SCR(43);
        SHA512_SCR(44); SHA512_SCR(45); SHA512_SCR(46); SHA512_SCR(47);
        SHA512_SCR(48); SHA512_SCR(49); SHA512_SCR(50); SHA512_SCR(51);
        SHA512_SCR(52); SHA512_SCR(53); SHA512_SCR(54); SHA512_SCR(55);
        SHA512_SCR(56); SHA512_SCR(57); SHA512_SCR(58); SHA512_SCR(59);
        SHA512_SCR(60); SHA512_SCR(61); SHA512_SCR(62); SHA512_SCR(63);
        SHA512_SCR(64); SHA512_SCR(65); SHA512_SCR(66); SHA512_SCR(67);
        SHA512_SCR(68); SHA512_SCR(69); SHA512_SCR(70); SHA512_SCR(71);
        SHA512_SCR(72); SHA512_SCR(73); SHA512_SCR(74); SHA512_SCR(75);
        SHA512_SCR(76); SHA512_SCR(77); SHA512_SCR(78); SHA512_SCR(79);

        wv[0] = ctx->h[0]; wv[1] = ctx->h[1];
        wv[2] = ctx->h[2]; wv[3] = ctx->h[3];
        wv[4] = ctx->h[4]; wv[5] = ctx->h[5];
        wv[6] = ctx->h[6]; wv[7] = ctx->h[7];

        j = 0;

        do {
            SHA512_EXP(0,1,2,3,4,5,6,7,j); j++;
            SHA512_EXP(7,0,1,2,3,4,5,6,j); j++;
            SHA512_EXP(6,7,0,1,2,3,4,5,j); j++;
            SHA512_EXP(5,6,7,0,1,2,3,4,j); j++;
            SHA512_EXP(4,5,6,7,0,1,2,3,j); j++;
            SHA512_EXP(3,4,5,6,7,0,1,2,j); j++;
            SHA512_EXP(2,3,4,5,6,7,0,1,j); j++;
            SHA512_EXP(1,2,3,4,5,6,7,0,j); j++;
        } while (j < 80);

        ctx->h[0] += wv[0]; ctx->h[1] += wv[1];
        ctx->h[2] += wv[2]; ctx->h[3] += wv[3];
        ctx->h[4] += wv[4]; ctx->h[5] += wv[5];
        ctx->h[6] += wv[6]; ctx->h[7] += wv[7];
    }
}

/* SHA-256 functions */

void sha256(const uint8_t *message, uint64_t len, uint8_t *digest)
{
    sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, message, len);
    sha256_final(&ctx, digest);
}

void sha256_init(sha256_ctx *ctx)
{
    ctx->h[0] = sha256_h0[0]; ctx->h[1] = sha256_h0[1];
    ctx->h[2] = sha256_h0[2]; ctx->h[3] = sha256_h0[3];
    ctx->h[4] = sha256_h0[4]; ctx->h[5] = sha256_h0[5];
    ctx->h[6] = sha256_h0[6]; ctx->h[7] = sha256_h0[7];

    ctx->len = 0;
    ctx->tot_len = 0;
}

void sha256_update(sha256_ctx *ctx, const uint8_t *message, uint64_t len)
{
    uint64_t block_nb;
    uint64_t new_len, rem_len, tmp_len;
    const uint8_t *shifted_message;

    tmp_len = SHA256_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], message, rem_len);

    if (ctx->len + len < SHA256_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA256_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha256_transf(ctx, ctx->block, 1);
    sha256_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA256_BLOCK_SIZE;

    memcpy(ctx->block, &shifted_message[block_nb << 6], rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 6;
}

void sha256_final(sha256_ctx *ctx, uint8_t *digest)
{
    uint64_t block_nb;
    uint64_t pm_len;
    uint64_t len_b;
    uint64_t tot_len;

    block_nb = (1 + ((SHA256_BLOCK_SIZE - 9)
                     < (ctx->len % SHA256_BLOCK_SIZE)));

    tot_len = ctx->tot_len + ctx->len;
    ctx->tot_len = tot_len;

    len_b = tot_len << 3;
    pm_len = block_nb << 6;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    UNPACK64(len_b, ctx->block + pm_len - 8);

    sha256_transf(ctx, ctx->block, block_nb);

   UNPACK32(ctx->h[0], &digest[ 0]);
   UNPACK32(ctx->h[1], &digest[ 4]);
   UNPACK32(ctx->h[2], &digest[ 8]);
   UNPACK32(ctx->h[3], &digest[12]);
   UNPACK32(ctx->h[4], &digest[16]);
   UNPACK32(ctx->h[5], &digest[20]);
   UNPACK32(ctx->h[6], &digest[24]);
   UNPACK32(ctx->h[7], &digest[28]);
}

/* SHA-512 functions */

void sha512(const uint8_t *message, uint64_t len, uint8_t *digest)
{
    sha512_ctx ctx;

    sha512_init(&ctx);
    sha512_update(&ctx, message, len);
    sha512_final(&ctx, digest);
}

void sha512_init(sha512_ctx *ctx)
{
    ctx->h[0] = sha512_h0[0]; ctx->h[1] = sha512_h0[1];
    ctx->h[2] = sha512_h0[2]; ctx->h[3] = sha512_h0[3];
    ctx->h[4] = sha512_h0[4]; ctx->h[5] = sha512_h0[5];
    ctx->h[6] = sha512_h0[6]; ctx->h[7] = sha512_h0[7];

    ctx->len = 0;
    ctx->tot_len = 0;
}

void sha512_update(sha512_ctx *ctx, const uint8_t *message, uint64_t len)
{
    uint64_t block_nb;
    uint64_t new_len, rem_len, tmp_len;
    const uint8_t *shifted_message;

    tmp_len = SHA512_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], message, rem_len);

    if (ctx->len + len < SHA512_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA512_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha512_transf(ctx, ctx->block, 1);
    sha512_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA512_BLOCK_SIZE;

    memcpy(ctx->block, &shifted_message[block_nb << 7], rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 7;
}

void sha512_final(sha512_ctx *ctx, uint8_t *digest)
{
    uint64_t block_nb;
    uint64_t pm_len;
    uint64_t len_b;
    uint64_t tot_len;

    block_nb = 1 + ((SHA512_BLOCK_SIZE - 17)
                     < (ctx->len % SHA512_BLOCK_SIZE));

    tot_len = ctx->tot_len + ctx->len;
    ctx->tot_len = tot_len;

    len_b = tot_len << 3;
    pm_len = block_nb << 7;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    UNPACK64(len_b, ctx->block + pm_len - 8);

    sha512_transf(ctx, ctx->block, block_nb);

    UNPACK64(ctx->h[0], &digest[ 0]);
    UNPACK64(ctx->h[1], &digest[ 8]);
    UNPACK64(ctx->h[2], &digest[16]);
    UNPACK64(ctx->h[3], &digest[24]);
    UNPACK64(ctx->h[4], &digest[32]);
    UNPACK64(ctx->h[5], &digest[40]);
    UNPACK64(ctx->h[6], &digest[48]);
    UNPACK64(ctx->h[7], &digest[56]);
}

/* HASH FUNCTIONS HMAC_SHA256 AND HMAC_SHA512 */

typedef struct {
    sha256_ctx ctx_inside;
    sha256_ctx ctx_outside;

    /* for hmac_reinit */
    sha256_ctx ctx_inside_reinit;
    sha256_ctx ctx_outside_reinit;

    unsigned char block_ipad[SHA256_BLOCK_SIZE];
    unsigned char block_opad[SHA256_BLOCK_SIZE];
} hmac_sha256_ctx;

typedef struct {
    sha512_ctx ctx_inside;
    sha512_ctx ctx_outside;

    /* for hmac_reinit */
    sha512_ctx ctx_inside_reinit;
    sha512_ctx ctx_outside_reinit;

    unsigned char block_ipad[SHA512_BLOCK_SIZE];
    unsigned char block_opad[SHA512_BLOCK_SIZE];
} hmac_sha512_ctx;

void hmac_sha256_init(hmac_sha256_ctx *ctx, const unsigned char *key, unsigned int key_size);
void hmac_sha256_reinit(hmac_sha256_ctx *ctx);
void hmac_sha256_update(hmac_sha256_ctx *ctx, const unsigned char *message, unsigned int message_len);
void hmac_sha256_final(hmac_sha256_ctx *ctx, unsigned char *mac, unsigned int mac_size);
void hmac_sha256(const unsigned char *key, unsigned int key_size, const unsigned char *message, unsigned int message_len, unsigned char *mac, unsigned mac_size);

void hmac_sha512_init(hmac_sha512_ctx *ctx, const unsigned char *key, unsigned int key_size);
void hmac_sha512_reinit(hmac_sha512_ctx *ctx);
void hmac_sha512_update(hmac_sha512_ctx *ctx, const unsigned char *message, unsigned int message_len);
void hmac_sha512_final(hmac_sha512_ctx *ctx, unsigned char *mac, unsigned int mac_size);
void hmac_sha512(const unsigned char *key, unsigned int key_size, const unsigned char *message, unsigned int message_len, unsigned char *mac, unsigned mac_size);

/* HMAC-SHA-256 functions */

void hmac_sha256_init(hmac_sha256_ctx *ctx, const unsigned char *key, unsigned int key_size)
{
    unsigned int fill;
    unsigned int num;

    const unsigned char *key_used;
    unsigned char key_temp[SHA256_DIGEST_SIZE];
    int i;

    if (key_size == SHA256_BLOCK_SIZE) {
        key_used = key;
        num = SHA256_BLOCK_SIZE;
    } else {
        if (key_size > SHA256_BLOCK_SIZE){
            num = SHA256_DIGEST_SIZE;
            sha256(key, key_size, key_temp);
            key_used = key_temp;
        } else { /* key_size > SHA256_BLOCK_SIZE */
            key_used = key;
            num = key_size;
        }
        fill = SHA256_BLOCK_SIZE - num;

        memset(ctx->block_ipad + num, 0x36, fill);
        memset(ctx->block_opad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ctx->block_ipad[i] = key_used[i] ^ 0x36;
        ctx->block_opad[i] = key_used[i] ^ 0x5c;
    }

    sha256_init(&ctx->ctx_inside);
    sha256_update(&ctx->ctx_inside, ctx->block_ipad, SHA256_BLOCK_SIZE);

    sha256_init(&ctx->ctx_outside);
    sha256_update(&ctx->ctx_outside, ctx->block_opad,
                  SHA256_BLOCK_SIZE);

    /* for hmac_reinit */
    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside,
           sizeof(sha256_ctx));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside,
           sizeof(sha256_ctx));
}

void hmac_sha256_reinit(hmac_sha256_ctx *ctx)
{
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit,
           sizeof(sha256_ctx));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit,
           sizeof(sha256_ctx));
}

void hmac_sha256_update(hmac_sha256_ctx *ctx, const unsigned char *message, unsigned int message_len)
{
    sha256_update(&ctx->ctx_inside, message, message_len);
}

void hmac_sha256_final(hmac_sha256_ctx *ctx, unsigned char *mac, unsigned int mac_size)
{
    unsigned char digest_inside[SHA256_DIGEST_SIZE];
    unsigned char mac_temp[SHA256_DIGEST_SIZE];

    sha256_final(&ctx->ctx_inside, digest_inside);
    sha256_update(&ctx->ctx_outside, digest_inside, SHA256_DIGEST_SIZE);
    sha256_final(&ctx->ctx_outside, mac_temp);
    memcpy(mac, mac_temp, mac_size);
}

void hmac_sha256(const unsigned char *key, unsigned int key_size, const unsigned char *message, unsigned int message_len, unsigned char *mac, unsigned mac_size)
{
    hmac_sha256_ctx ctx;

    hmac_sha256_init(&ctx, key, key_size);
    hmac_sha256_update(&ctx, message, message_len);
    hmac_sha256_final(&ctx, mac, mac_size);
}

/* HMAC-SHA-512 functions */

void hmac_sha512_init(hmac_sha512_ctx *ctx, const unsigned char *key, unsigned int key_size)
{
    unsigned int fill;
    unsigned int num;

    const unsigned char *key_used;
    unsigned char key_temp[SHA512_DIGEST_SIZE];
    int i;

    if (key_size == SHA512_BLOCK_SIZE) {
        key_used = key;
        num = SHA512_BLOCK_SIZE;
    } else {
        if (key_size > SHA512_BLOCK_SIZE){
            num = SHA512_DIGEST_SIZE;
            sha512(key, key_size, key_temp);
            key_used = key_temp;
        } else { /* key_size > SHA512_BLOCK_SIZE */
            key_used = key;
            num = key_size;
        }
        fill = SHA512_BLOCK_SIZE - num;

        memset(ctx->block_ipad + num, 0x36, fill);
        memset(ctx->block_opad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ctx->block_ipad[i] = key_used[i] ^ 0x36;
        ctx->block_opad[i] = key_used[i] ^ 0x5c;
    }

    sha512_init(&ctx->ctx_inside);
    sha512_update(&ctx->ctx_inside, ctx->block_ipad, SHA512_BLOCK_SIZE);

    sha512_init(&ctx->ctx_outside);
    sha512_update(&ctx->ctx_outside, ctx->block_opad,
                  SHA512_BLOCK_SIZE);

    /* for hmac_reinit */
    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside,
           sizeof(sha512_ctx));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside,
           sizeof(sha512_ctx));
}

void hmac_sha512_reinit(hmac_sha512_ctx *ctx)
{
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit,
           sizeof(sha512_ctx));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit,
           sizeof(sha512_ctx));
}

void hmac_sha512_update(hmac_sha512_ctx *ctx, const unsigned char *message, unsigned int message_len)
{
    sha512_update(&ctx->ctx_inside, message, message_len);
}

void hmac_sha512_final(hmac_sha512_ctx *ctx, unsigned char *mac, unsigned int mac_size)
{
    unsigned char digest_inside[SHA512_DIGEST_SIZE];
    unsigned char mac_temp[SHA512_DIGEST_SIZE];

    sha512_final(&ctx->ctx_inside, digest_inside);
    sha512_update(&ctx->ctx_outside, digest_inside, SHA512_DIGEST_SIZE);
    sha512_final(&ctx->ctx_outside, mac_temp);
    memcpy(mac, mac_temp, mac_size);
}

void hmac_sha512(const unsigned char *key, unsigned int key_size, const unsigned char *message, unsigned int message_len, unsigned char *mac, unsigned mac_size)
{
    hmac_sha512_ctx ctx;

    hmac_sha512_init(&ctx, key, key_size);
    hmac_sha512_update(&ctx, message, message_len);
    hmac_sha512_final(&ctx, mac, mac_size);
}

/* BNZ DEFINES */

typedef struct {
    size_t sign;
    size_t size;
    uint8_t *digits;
} bnz_t;

/* BNZ GLOBAL VARIABLES */

int8_t char_16[256] = { // ascii - hex
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  10,  11,  12,  13,  14,  15,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  10,  11,  12,  13,  14,  15,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1
};

int8_t char_32[256] = { // ascii - Bech32
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    15,  -1,  10,  17,  21,  20,  26,  30,   7,   5,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  29,  -1,  24,  13,  25,   9,   8,  23,  -1,  18,  22,  31,  27,  19,  -1,
     1,   0,   3,  16,  11,  28,  12,  14,   6,   4,   2,  -1,  -1,  -1,  -1,  -1,
    -1,  29,  -1,  24,  13,  25,   9,   8,  23,  -1,  18,  22,  31,  27,  19,  -1,
     1,   0,   3,  16,  11,  28,  12,  14,   6,   4,   2,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1
};

int8_t char_58[256] = { // ascii - Bitcoin base 58
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,   0,   1,   2,   3,   4,   5,   6,   7,   8,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,   9,  10,  11,  12,  13,  14,  15,  16,  -1,  17,  18,  19,  20,  21,  -1,
    22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,  -1,  -1,  -1,  -1,  -1,
    -1,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  -1,  44,  45,  46,
    47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1
};

int8_t char_64[256] = { // ascii - base 64
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  62,  -1,  -1,  -1,  63,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
    15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  -1,  -1,  -1,  -1,  -1,
    -1,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
    41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1
};

int8_t char_d[256] = {  // ascii - general
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,
    25,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  -1,  -1,  -1,  -1,  62,
    -1,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,
    51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1
};

/* BNZ FUNCTIONS */

uint8_t *init_uint8_array(uint32_t);

void bnz_init(bnz_t *);
void bnz_resize(bnz_t *, size_t, bool);
void bnz_align(bnz_t *, bnz_t *);
void bnz_reverse_digits(bnz_t *); 
void bnz_shift_r(bnz_t *, uint32_t);
void bnz_trim(bnz_t *);
void bnz_print(const bnz_t *, int32_t, const char *);
void bnz_free(bnz_t *);

int8_t get_digit(const char *, size_t, uint8_t);
uint8_t *get_base_n_str(const bnz_t *, uint32_t, const char *, uint32_t *);

void bnz_rnd(bnz_t *, uint32_t);
void bnz_set_i32(bnz_t *, int32_t);
void bnz_set_ui32(bnz_t *, uint32_t);
void bnz_set_str(bnz_t *, const char *, uint8_t);
void bnz_set_bnz(bnz_t *, const bnz_t *);

int32_t cmp_uint8_arr(uint8_t *, uint8_t *, size_t);
int32_t bnz_cmp_i32(const bnz_t *, int32_t);
int32_t bnz_cmp_bnz(const bnz_t *, const bnz_t *);
bool bnz_is_zero(const bnz_t *);
bool bnz_bit_set(const bnz_t *, uint32_t);

void bnz_concatenate_ui8(bnz_t *, const bnz_t *, uint8_t, size_t);
void bnz_concatenate_bnz(bnz_t *, const bnz_t *, const bnz_t *, size_t);

void bnz_add_i32(bnz_t *, const bnz_t *, int32_t);
void bnz_add_bnz(bnz_t *, const bnz_t *, const bnz_t *);
void bnz_addition(bnz_t *, const bnz_t *, const bnz_t *);
void bnz_subtract_bnz(bnz_t *, const bnz_t *, const bnz_t *);
void bnz_subtraction(bnz_t *, const bnz_t *, const bnz_t *);
void bnz_multiply_i32(bnz_t *, const bnz_t *, int32_t);
void bnz_multiply_bnz(bnz_t *, const bnz_t *, const bnz_t *);
void bnz_divide_bnz(bnz_t *, bnz_t *, const bnz_t *, const bnz_t *);
void bnz_division(bnz_t *, bnz_t *, const bnz_t *, const bnz_t *);
void bnz_division_signs(bnz_t *, bnz_t *, const bnz_t *, const bnz_t *);
void bnz_mod_bnz(bnz_t *, const bnz_t *, const bnz_t *);

void bnz_mod_pow(bnz_t *, const bnz_t *, const bnz_t *, const bnz_t *);
void bnz_modular_multiplicative_inverse(bnz_t *, const bnz_t *, const bnz_t *);

uint8_t *init_uint8_array(uint32_t len) // allocate and zero a one dimensional uint8_t array of length len
{
    uint8_t *uint8_array = NULL;

    uint8_array = malloc(len);
    if (!uint8_array) {
        return NULL;
    }
    memset(uint8_array, 0, len);

    return uint8_array;
}

void bnz_init(bnz_t *a) // initiate bnz_t components
{
    a->sign = 0;
    a->size = 0;
    a->digits = NULL;
}

void bnz_resize(bnz_t *a, size_t new_size, bool preserve) // increase or decrease number of bytes in a->digits, zeroing added bytes, and preserving or zeroing existing bytes
{
    uint8_t *tmp = NULL;
    size_t prev_size = a->size;

    if (new_size < 1) new_size = 1;

    tmp = realloc(a->digits, new_size); // if realloc is successful, a->digits will be freed automatically. If realloc fails, tmp will be NULL, and a->digits will remain unchanged.

    if (tmp) {
        if (preserve == true) { // if preserve is true, the original byte values and the sign will be preserved
            if (new_size > prev_size) { // if the new size is larger than the original size...
                memset(tmp + prev_size, 0, new_size - prev_size); // ...zero the new bytes
            }
        } else { // if preserve is false, all byte values will be zeroed and the sign will be set to positive
            a->sign = 0; // set sign to positive
            memset(tmp, 0, new_size); // zero all bytes
        }
        a->digits = tmp; // replace a->digits with tmp
        a->size = new_size; // set new size
    }
}

void bnz_align(bnz_t *a, bnz_t *b) // resize a->digits or b->digits to match the byte count of the longer of a and b
{
    bnz_trim(a);
    bnz_trim(b);
    if (a->size > b->size) {
        bnz_resize(b, a->size, true);
    } else {
        bnz_resize(a, b->size, true);
    }
}

void bnz_reverse_digits(bnz_t *a) // reverse the order of the bytes in a->digits
{
    uint8_t tmp;
    size_t i = 0, j = a->size - 1;

    while (i < j) {
        tmp = a->digits[i];
        a->digits[i] = a->digits[j];
        a->digits[j] = tmp;
        i++;
        j--;
    }
}

void bnz_shift_r(bnz_t *a, uint32_t sh) // shift the bits in a->digits to the right by sh bits, adding 0 value bits to msb end
{
    uint8_t msk = 255 >> (8 - sh);
    size_t i, orig_size = a->size;

    if (sh < 1 || sh > 7) return;

    bnz_resize(a, orig_size + 1, true);
    bnz_reverse_digits(a);

    for (i = a->size - 1; i > 0; i--) {
        a->digits[i] = (a->digits[i - 1] & msk) << (8 - sh) | a->digits[i] >> sh;
    }

    bnz_reverse_digits(a);
    bnz_resize(a, orig_size, true);
}

void bnz_trim(bnz_t *a) // trim 0 value bytes from msb end of a->digits
{
    size_t new_size = a->size;

    while (a->digits[new_size - 1] == 0 && new_size >= 0) {
        new_size--;
    }

    bnz_resize(a, new_size, true);
}

void bnz_print(const bnz_t *a, int32_t base, const char *txt) // print a in a given base, preceded by optional string txt
{
    uint8_t *str = NULL;
    uint32_t i, j, len;
    bnz_t tmp;

    bnz_init(&tmp);

    bnz_set_bnz(&tmp, a);

    bnz_reverse_digits(&tmp);

    switch (base) {
        case -2: // binary with spaces between bytes
            printf("%s", txt);
            if (bnz_is_zero(&tmp) == true) {
                printf("0\n");
            } else {
                if (tmp.sign) printf("-");
                for (i = 0; i < tmp.size; i++) { // traverse bytes
                    for (j = 0; j < 8; j++) { // divide each byte into 8 bits
                        printf("%d", (tmp.digits[i] >> (7 - j)) & 1);
                    }
                    printf(" "); // add space between each byte
                }
                printf("\n");
            }
            break;
        case 2: // binary
            printf("%s", txt);
            if (bnz_is_zero(&tmp) == true) {
                printf("0\n");
            } else {
                if (tmp.sign) printf("-");
                for (i = 0; i < tmp.size; i++) { // traverse bytes
                    for (j = 0; j < 8; j++) { // divide each byte into 8 bits
                        printf("%d", (tmp.digits[i] >> (7 - j)) & 1);
                    }
                }
                printf("\n");
            }
            break;
        case -16: // hex, upper case, without "0x" prefix, same as default for 0 to F
            printf("%s", txt);
            if (bnz_is_zero(&tmp) == true) {
                printf("0\n");
            } else {
                str = get_base_n_str(&tmp, 16, "0123456789ABCDEF", &len);
                if (!str) {
                    return;
                }
                if (tmp.sign) printf("-");
                printf("%s\n", str);
            }
            break;
        case 16: // hex, lower case with "0x" prefix
            printf("%s", txt);
            if (bnz_is_zero(&tmp) == true) {
                printf("0x0\n");
            } else {
                if (tmp.sign) printf("-");
                printf("0x");
                for (i = 0; i < tmp.size; i++) {
                    printf("%02x", tmp.digits[i]);
                }
                printf("\n");
            }
            break;
        case -32: // standard base 32
            printf("%s", txt);
            if (bnz_is_zero(&tmp) == true) {
                printf("0\n");
            } else {
                str = get_base_n_str(&tmp, 32, "0123456789ABCDEFGHIJKLMNOPQRSTUV", &len);
                if (!str) {
                    return;
                }
                if (tmp.sign) printf("-");
                printf("%s\n", str);
            }
            break;
        case 32: // bech32
            printf("%s", txt);
            if (bnz_is_zero(&tmp) == true) {
                printf("q\n");
            } else {
                str = get_base_n_str(&tmp, 32, "qpzry9x8gf2tvdw0s3jn54khce6mua7l", &len);
                if (!str) {
                    return;
                }
                if (tmp.sign) printf("-");
                printf("%s\n", str);
            }
            break;
        case -58: // standard base 58
            printf("%s", txt);
            if (bnz_is_zero(&tmp) == true) {
                printf("0\n");
            } else {
                str = get_base_n_str(&tmp, 58, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv", &len);
                if (!str) {
                    return;
                }
                if (tmp.sign) printf("-");
                if (tmp.sign) printf("-");
                printf("%s\n", str);
            }
            break;
        case 58: // bitcoin base 58
            printf("%s", txt);
            if (bnz_is_zero(&tmp) == true) {
                printf("1\n");
            } else {
                str = get_base_n_str(&tmp, 58, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", &len);
                if (!str) {
                    return;
                }
                if (tmp.sign) printf("-");
                printf("%s\n", str);
            }
            break;
        case 64:
            printf("%s", txt);
            if (bnz_is_zero(&tmp) == true) {
                printf("A\n");
            } else {
                str = get_base_n_str(&tmp, 64, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", &len);
                if (!str) {
                    return;
                }
                if (tmp.sign) printf("-");
                printf("%s\n", str);
            }
            break;
        case 256: // individual byte values, base 10, separated by ", "
            printf("%s", txt);
            if (bnz_is_zero(&tmp) == true) {
                printf("0\n");
            } else {
                if (tmp.sign) printf("-");
                printf("%d", tmp.digits[0]);
                for (i = 1; i < tmp.size; i++) {
                    printf(", %d", tmp.digits[i]);
                }
                printf("\n");
            }
            break;
        default: // default for 2 to 63
            printf("%s", txt);
            if (bnz_is_zero(&tmp) == true) {
                printf("0\n");
            } else {
                if (base >= 2 && base <= 63) {
                    str = get_base_n_str(&tmp, base, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_", &len);
                    if (!str) {
                        return;
                    }
                    if (tmp.sign) printf("-");
                    printf("%s\n", str);
                }
            }
            break;
    }

    bnz_free(&tmp);
    free(str);
}

void bnz_free(bnz_t *a) // free bnz_t resources
{
    a->sign = 0;
    a->size = 0;
    free(a->digits);
    a->digits = NULL;
}

int8_t get_digit(const char *str, size_t idx, uint8_t base) // return numerical value of char at index idx of str which represents a number in the given base and in big endian order
{
    int8_t dgt = -1;

    switch (base) {
        case 16:
            dgt = char_16[str[idx]];
            break;
        case 32:
            dgt = char_32[str[idx]];
            break;
        case 58:
            dgt = char_58[str[idx]];
            break;
        case 64:
            dgt = char_64[str[idx]];
            break;
        default:
            if (base >= 2 && base <= 63) dgt = char_d[str[idx]];
            break;
    }

    if (dgt < 0 || dgt >= base) return -1;

    return dgt;
}

uint8_t *get_base_n_str(const bnz_t *a, uint32_t base, const char *alpha, uint32_t *len) // return a null terminated string representing a->digits in given base, big endian order
{
    uint8_t *base_n_str = NULL, *base_n_str_trimmed = NULL;
    size_t i, j, k, trim = 0;

    (*len) = (a->size * log10((double)256)) / log10((double)abs(base)) + 1;

    base_n_str = init_uint8_array((*len) + 1);
    if (!base_n_str) {
        return NULL;
    }

    for (i = 0; i < a->size; i++) {
        k = a->digits[i];
        for (j = (*len); j > 0; j--) {
            k += (uint32_t)base_n_str[j - 1] * 256;
            base_n_str[j - 1] = (uint8_t)(k % abs(base));
            k /= abs(base);
        }
    }

    while ((base == 32 && alpha[base_n_str[trim]] == 'q') || (base == 58 && alpha[base_n_str[trim]] == '1') || (base == 64 && alpha[base_n_str[trim]] == 'A') || (base != 64 && alpha[base_n_str[trim]] == '0')) { // trim leading zeros at msb end, 'q' for Bech32, '1' for Bitcoin base 58, 'A' for base 64
        trim++;
        (*len)--;
    }

    base_n_str_trimmed = init_uint8_array((*len) + 1);
    if (!base_n_str_trimmed) {
        free(base_n_str);
        return NULL;
    }

    for (i = 0; i < (*len); i++) {
        base_n_str_trimmed[i] = alpha[base_n_str[i + trim]];
    }

    free(base_n_str);
    return base_n_str_trimmed;
}

void bnz_rnd(bnz_t *rnd, uint32_t size) // generate random number with size bytes as a bnz_t
{
    uint32_t random;
    size_t i;

    bnz_resize(rnd, size, false);

    for (i = 0; i < size; i++) {
        rand_s(&random); // on non-Windows systems, change this to some other source of cryptographically secure random numbers
        rnd->digits[i] = (uint8_t)(random & 255); // rnd->digits[i] = last byte of random
    }
}

void bnz_set_i32(bnz_t *res, int32_t val) // set bnz_t to 32 bit signed int, if the resultant bnz_t has leading zeros, these are trimmed
{
    if (val < 0) { // val is negative
        res->sign = 1; // sign == 1 for negative val, 0 for positive val
        val *= -1; // multiply negative int32_t by -1 to de-complement bytes
    }
    bnz_resize(res, 4, false); // resize res to 4 bytes, zero bytes
    memcpy(res->digits, &val, 4); // copy bytes from val to res->digits
    bnz_trim(res); // trim zero bytes from msb end
}

void bnz_set_ui32(bnz_t *res, uint32_t val) // set bnz_t to 32 bit uint32_t, if the resultant bnz_t has leading zeros, these are trimmed
{
    bnz_resize(res, 4, false); // resize res to 4 bytes, zero bytes
    memcpy(res->digits, &val, 4); // copy bytes from val to res->digits
    bnz_trim(res); // trim zero bytes from msb end
}

void bnz_set_str(bnz_t *res, const char *str, uint8_t base) // set bnz_t to number represented by str with radix between 2 and 64, and with its digits in big endian order
{
    int32_t dgt;
    size_t i, j, len = (size_t)((double)strlen(str) * log(base)/log(256)) + 1, idx = 0;

    bnz_resize(res, len, false);

    if (str[0] == '-') { // if first symbol of str is "-", set sign to 1 and set starting index of digits to 1 
        res->sign = 1;
        idx = 1;
    }

    for (i = idx; i < strlen(str); i++) {
        dgt = get_digit(str, i, base);
        if (dgt != -1) {
            for (j = len; j > 0; j--) {
                dgt += res->digits[j - 1] * base;
                res->digits[j - 1] = dgt & 255;
                dgt >>= 8;
            }
        }
    }

    bnz_reverse_digits(res); // convert a->digits to little endian order
    bnz_trim(res); // trim zero bytes from msb end
}

void bnz_set_bnz(bnz_t *res, const bnz_t *val) // set bnz_t equivalent to another bnz_t
{
    bnz_resize(res, val->size, false);
    memcpy(res->digits, val->digits, val->size);
    res->sign = val->sign;
}

int32_t cmp_uint8_arr(uint8_t *a, uint8_t *b, size_t len) // compare two 1D uint8_t arrays a and b, from msb to lsb, return -1 if a < b, 0 if a == b, and 1 if a > b 
{
    size_t idx = len;

    while (idx--) {
        if (a[idx] > b[idx]) return 1;
        if (a[idx] < b[idx]) return -1;
    }

    return 0;
}

int32_t bnz_cmp_i32(const bnz_t *a, int32_t b) // compare bnz_t with int32_t by converting int32_t to bnz_t and invoking bnz_cmp_bnz
{
    int32_t res;
    bnz_t tmp;
    bnz_init(&tmp);
    bnz_set_i32(&tmp, b);
    res = bnz_cmp_bnz(a, &tmp);
    bnz_free(&tmp);
    return res;
}

int32_t bnz_cmp_bnz(const bnz_t *a, const bnz_t *b) // compare two bnz_t numbers, taking account of signs, and invoking cmp_uint8_arr to compare their digits
{
    size_t res;
    bnz_t aa, bb;

    bnz_init(&aa);
    bnz_init(&bb);
    
    bnz_set_bnz(&aa, a);
    bnz_set_bnz(&bb, b);
    bnz_align(&aa, &bb);
    
    if (aa.sign != bb.sign) { // signs are different
        if (aa.sign == 0 && bb.sign != 0) {
            res = 1; // a > -b
        } else {
            res = -1; // -a < b
        }
    } else { // signs are the same
        res = cmp_uint8_arr(aa.digits, bb.digits, aa.size); // compare |a| and |b|
        switch (res) {
            case -1: // |a| < |b| => a < b, -a > -b
                if (aa.sign) res = 1; // reverse cmp value if a and b are negative
                break;
            case 1: // |a| > |b| => a > b, -a < -b
                if (aa.sign) res = -1; // reverse cmp value if a and b are negative
                break;
            default:
                break;
        }
    }

    bnz_free(&aa);
    bnz_free(&bb);

    return res;
}

bool bnz_is_zero(const bnz_t *val) // return true if val == 0, return false if val != 0
{
    size_t i;

    for (i = 0; i < val->size; i++) {
        if (val->digits[i] != 0) {
            return false;
        }
    }

    return true;
}

bool bnz_bit_set(const bnz_t *val, uint32_t idx) // return true if the specified bit in val is set, return false if it is not set
{
    uint32_t byte = idx / 8, bit = idx % 8;
    return (bool)((val->digits[byte] >> bit) & 1);
}

void bnz_concatenate_ui8(bnz_t *res, const bnz_t *a, uint8_t b, size_t order) // convert uint8_t to bnz_t and invoke bnz_concatenate_bnz
{
    bnz_t bb;
    bnz_init(&bb);
    bnz_resize(&bb, 1, false);
    memcpy(bb.digits, &b, 1);
    bnz_concatenate_bnz(res, a, &bb, order);
    bnz_free(&bb);
}

void bnz_concatenate_bnz(bnz_t *res, const bnz_t *a, const bnz_t *b, size_t order) // res = a || b, in specified order
{
    bnz_t tmp; // local variable permits a = a || b, a = b || a
    bnz_init(&tmp);
    bnz_resize(&tmp, a->size + b->size, false);
    if (order) {
        memcpy(tmp.digits, b->digits, b->size);
        memcpy(tmp.digits + b->size, a->digits, a->size);
    } else {
        memcpy(tmp.digits, a->digits, a->size);
        memcpy(tmp.digits + a->size, b->digits, b->size);
    }
    bnz_set_bnz(res, &tmp);
    bnz_free(&tmp);
}

void bnz_add_i32(bnz_t *res, const bnz_t *a, int32_t b) // convert int32_t to bnz_t and invoke bnz_add_bnz
{
    bnz_t bb;
    bnz_init(&bb);
    bnz_set_i32(&bb, b); // convert b to bnz_t
    bnz_add_bnz(res, a, &bb);
    bnz_free(&bb);
}

void bnz_add_bnz(bnz_t *res, const bnz_t *a, const bnz_t *b) // res = a + b, taking account of signs, invoking bnz_addition or bnz_subtraction
{
    int32_t cmp;
    bnz_t tmp, aa, bb;

    bnz_init(&tmp);
    bnz_init(&aa);
    bnz_init(&bb);

    bnz_set_bnz(&aa, a);
    bnz_set_bnz(&bb, b);

    bnz_align(&aa, &bb);

    cmp = cmp_uint8_arr(aa.digits, bb.digits, aa.size);

    if (a->sign) { // -a
        if (b->sign) { // -a, -b
            bnz_addition(&tmp, &aa, &bb);
            tmp.sign = 1;
        } else { // -a, +b
            if (cmp == -1) { // |a| < |b|
                bnz_subtraction(&tmp, &bb, &aa);
                tmp.sign = 0;
            } else { // |a| >= |b|
                bnz_subtraction(&tmp, &aa, &bb);
                tmp.sign = 1;
            }
        }
    } else { // +a
        if (b->sign) { // +a, -b
            if (cmp == -1) { // |a| < |b|
                bnz_subtraction(&tmp, &bb, &aa);
                tmp.sign = 1;
            } else { // |a| >= |b|
                bnz_subtraction(&tmp, &aa, &bb);
                tmp.sign = 0;
            }
        } else { // +a, +b
            bnz_addition(&tmp, &aa, &bb);
        }
    }

    bnz_trim(&tmp);

    bnz_set_bnz(res, &tmp);

    bnz_free(&tmp);
    bnz_free(&aa);
    bnz_free(&bb);
}

void bnz_addition(bnz_t *res, const bnz_t *a, const bnz_t *b) // res = |a| + |b|
{
    size_t i, carry = 0;
    bnz_t tmp;
    bnz_init(&tmp);
    bnz_resize(&tmp, a->size + 1, false);
    for (i = 0; i < a->size; i++) {
        tmp.digits[i] = a->digits[i] + carry;
        carry = tmp.digits[i] < carry ? 1 : 0;
        tmp.digits[i] += b->digits[i];
        if (tmp.digits[i] < b->digits[i]) carry = 1;
    }
    tmp.digits[a->size] = carry;
    bnz_set_bnz(res, &tmp);
    bnz_free(&tmp);
}

void bnz_subtract_bnz(bnz_t *res, const bnz_t *a, const bnz_t *b) // res = a - b, taking account of signs, invoking bnz_subtraction or bnz_addition
{
    int32_t cmp;
    bnz_t tmp, aa, bb;

    bnz_init(&tmp);
    bnz_init(&aa);
    bnz_init(&bb);

    bnz_set_bnz(&aa, a);
    bnz_set_bnz(&bb, b);

    bnz_align(&aa, &bb);

    cmp = cmp_uint8_arr(aa.digits, bb.digits, aa.size);

    if (a->sign) { // -a
        if (b->sign) { // -a, -b
            if (cmp == -1) { // |a| < |b|
                bnz_subtraction(&tmp, &bb, &aa);
                tmp.sign = 0;
            } else { // |a| >= |b|
                bnz_subtraction(&tmp, &aa, &bb);
                tmp.sign = 1;
            }
        } else { // -a, +b
            bnz_addition(&tmp, &aa, &bb);
            tmp.sign = 1;
        }
    } else { // +a
        if (b->sign) { // +a, -b
            bnz_addition(&tmp, &aa, &bb);
            tmp.sign = 0;
        } else { // +a, +b
            if (cmp == -1) { // |a| < |b|
                bnz_subtraction(&tmp, &bb, &aa);
                tmp.sign = 1;
            } else { // |a| >= |b|
                bnz_subtraction(&tmp, &aa, &bb);
                tmp.sign = 0;
            }
        }
    }

    bnz_trim(&tmp);

    bnz_set_bnz(res, &tmp);

    bnz_free(&tmp);
    bnz_free(&aa);
    bnz_free(&bb);
}

void bnz_subtraction(bnz_t *res, const bnz_t *a, const bnz_t *b) // res = |a| - |b|
{
    size_t i, borrow = 0;
    bnz_t tmp;
    bnz_init(&tmp);
    bnz_resize(&tmp, a->size, false);
    for (i = 0; i < a->size; i++) {
        tmp.digits[i] = a->digits[i] - borrow;
        borrow = tmp.digits[i] > 255 - borrow ? 1 : 0;
        tmp.digits[i] -= b->digits[i];
        if (tmp.digits[i] > 255 - b->digits[i]) borrow = 1;
    }
    bnz_set_bnz(res, &tmp);
    bnz_free(&tmp);
}

void bnz_multiply_i32(bnz_t *res, const bnz_t *a, int32_t b) // convert int32_t to bnz_t and invoke bnz_multiply_bnz
{
    bnz_t bb;
    bnz_init(&bb);
    bnz_set_i32(&bb, b);
    bnz_multiply_bnz(res, a, &bb);
    bnz_free(&bb);
}

void bnz_multiply_bnz(bnz_t *res, const bnz_t *a, const bnz_t *b) // res = |a| * |b|
{
    uint8_t k, t[2];
    uint16_t m;
    size_t i, j;
    bnz_t tmp, aa, bb;

    bnz_init(&tmp);
    bnz_init(&aa);
    bnz_init(&bb);

    bnz_set_bnz(&aa, a);
    bnz_set_bnz(&bb, b);

    bnz_align(&aa, &bb);
    bnz_resize(&tmp, aa.size * 2, false);

    if (a->sign) { // -a
        if (b->sign) { // -a, -b
            tmp.sign = 0;
        } else { // -a, +b
            tmp.sign = 1;
        }
    } else { // +a
        if (b->sign) { // +a, -b
            tmp.sign = 1;
        } else { // +a, +b
            tmp.sign = 0;
        }
    }

    for (i = 0; i < aa.size; i++) {
        if (bb.digits[i] == 0) {
            tmp.digits[i + aa.size] = 0;
        } else {
            k = 0;
            for (j = 0; j < aa.size; j++) {
                m = aa.digits[j] * bb.digits[i];
                t[0] = (m & 255) + k;
                t[1] = (m >> 8) & 255;
                if (t[0] < k) t[1]++;
                t[0] += tmp.digits[j + i];
                if (t[0] < tmp.digits[j + i]) t[1]++;
                tmp.digits[j + i] = t[0];
                k = t[1];
            }    
            tmp.digits[i + aa.size] = k;
        }
    }

    bnz_trim(&tmp);

    bnz_set_bnz(res, &tmp);

    bnz_free(&tmp);
    bnz_free(&aa);
    bnz_free(&bb);
}

void bnz_divide_bnz(bnz_t *q, bnz_t *r, const bnz_t *a, const bnz_t *b) // get q and r of a / b, taking account of signs, invoking bnz_division
{
    int32_t cmp;

    bnz_t aa, bb;

    bnz_init(&aa);
    bnz_init(&bb);

    bnz_set_bnz(&aa, a);
    bnz_set_bnz(&bb, b);
    bnz_trim(&aa);
    bnz_trim(&bb);

    aa.sign = 0;
    bb.sign = 0;

    if (bnz_is_zero(&bb) == true) { // divide by 0
        printf("div 0 error\n");
        bnz_set_i32(q, 0);
        bnz_set_i32(r, 0);
        return;
    }

    cmp = bnz_cmp_bnz(&aa, &bb);

    if (cmp == 0) { // |aa| = |bb|
        bnz_set_i32(q, 1);
        bnz_set_i32(r, 0);
        bnz_division_signs(q, r, a, b);
        bnz_free(&aa);
        bnz_free(&bb);
        return;
    }

    if (cmp == -1) { // |aa| < |bb|
        bnz_set_i32(q, 0);
        bnz_set_bnz(r, &aa);
        bnz_division_signs(q, r, a, b);
        bnz_free(&aa);
        bnz_free(&bb);
        return;
    }

    bnz_division(q, r, &aa, &bb); // |aa| > |bb|
    bnz_division_signs(q, r, a, b);

    bnz_free(&aa);
    bnz_free(&bb);   
}

void bnz_division(bnz_t *q, bnz_t *r, const bnz_t *a, const bnz_t *b) // get q and r of |a| / |b|
{
    uint8_t *an = NULL, *bn = NULL, tmp = b->digits[b->size - 1];
    uint16_t q_hat, r_hat, p, base = 256;
    int32_t sh = 0, i, j, t, k;

    bnz_resize(q, a->size - b->size + 1, false);
    bnz_resize(r, b->size, false);

    while (tmp < 128) { // measure left shift required to ensure that the highest bit of bn->digits[bn->size - 1] is set
        sh++;
        tmp <<= 1;
    }

    // an
    an = init_uint8_array(2 * (a->size + 1));
    if (!an) {
        return;
    }

    an[a->size] = a->digits[a->size - 1] >> (8 - sh);
    for (i = a->size - 1; i > 0; i--) {
        an[i] = (a->digits[i] << sh) | (a->digits[i-1] >> (8 - sh));
    }
    an[0] = a->digits[0] << sh;

    // bn
    bn = init_uint8_array(2 * b->size);
    if (!bn) {
        free(an);
        return;
    }
    for (i = b->size - 1; i > 0; i--) {
        bn[i] = (b->digits[i] << sh) | (b->digits[i - 1] >> (8 - sh));
    }
    bn[0] = b->digits[0] << sh;

    // main loop
    for (j = a->size - b->size; j >= 0; j--) {
        q_hat = ((an[j + b->size] * base) + an[j + b->size - 1]) / bn[b->size - 1];
        r_hat = ((an[j + b->size] * base) + an[j + b->size - 1]) - (q_hat * bn[b->size - 1]);

        // q_hat adjustment, maximum 2 iterations
        if (q_hat >= base || q_hat * bn[b->size - 2] > (base * r_hat) + an[j + b->size - 2]) { // first iteration
            q_hat -= 1;
            r_hat += bn[b->size - 1];
            if (r_hat < base) { // second iteration
                if (q_hat >= base || q_hat * bn[b->size - 2] > (base * r_hat) + an[j + b->size - 2]) {
                    q_hat -= 1;
                    r_hat += bn[b->size - 1];
                }
            }
        }

        k = 0;
        for (i = 0; i < b->size; i++) {
            p = q_hat * bn[i];
            t = an[i + j] - k - (p & 255);
            an[i + j] = t;
            k = (p >> 8) - (t >> 8);
        }
        t = an[j + b->size] - k;
        an[j + b->size] = t;

        q->digits[j] = q_hat;

        if (t < 0) {
            k = 0;
            q->digits[j] = q->digits[j] - 1;
            for (i = 0; i < b->size; i++) {
                t = an[i + j] + bn[i] + k;
                an[i + j] = t;
                k = t >> 8;
            }
            an[j + b->size] = an[j + b->size] + k;
        }
    }

    for (i = 0; i < b->size; i++) {
        r->digits[i] = (an[i] >> sh) | (an[i + 1] << (8 - sh));
    }

    bnz_trim(q);
    bnz_trim(r);

    free(an);
    free(bn);
}

void bnz_division_signs(bnz_t *q, bnz_t *r, const bnz_t *a, const bnz_t *b) // process signs of q and r in a / b
{
    if (a->sign) { // -a
        if (b->sign) { // -a, -b
            q->sign = 0; // +q
            r->sign = 1; // -r
        } else { // -a, +b
            q->sign = 1; // -q
            r->sign = 1; // -r
        }
    } else { // +a
        if (b->sign) { // +a, -b
            q->sign = 1; // -q
            r->sign = 0; // +r
        } else { // +a, +b
            q->sign = 0; // +q
            r->sign = 0; // +r
        }
    }
}

void bnz_mod_bnz(bnz_t *res, const bnz_t *a, const bnz_t *b) // res = a % b, invoking bnz_divide_bnz
{
    bnz_t q, r;

    bnz_init(&q);
    bnz_init(&r);
    
    bnz_divide_bnz(&q, &r, a, b);
    bnz_trim(&r);
    if (r.sign) bnz_add_bnz(&r, &r, b);
    bnz_set_bnz(res, &r);

    bnz_free(&q);
    bnz_free(&r);
}

void bnz_mod_pow(bnz_t *res, const bnz_t *a, const bnz_t *b, const bnz_t *c) // get res = a^b mod c, code adapted from the pseudocode at https://en.wikipedia.org/wiki/Modular_exponentiation
{
    bnz_t aa, bb;

    bnz_init(&aa);
    bnz_init(&bb);

    bnz_set_i32(res, 1);
    bnz_set_bnz(&aa, a);
    bnz_set_bnz(&bb, b);

    while (bnz_cmp_i32(&bb, 0) == 1) {
        if (bnz_bit_set(&bb, 0) == true) {
            bnz_multiply_bnz(res, res, &aa);
            bnz_mod_bnz(res, res, c);
        }
        bnz_multiply_bnz(&aa, &aa, &aa);
        bnz_mod_bnz(&aa, &aa, c);
        bnz_shift_r(&bb, 1);
    }

    bnz_free(&aa);
    bnz_free(&bb);
}

void bnz_modular_multiplicative_inverse(bnz_t *res, const bnz_t *a, const bnz_t *b) // get res where (res * a) mod b = 1, code adapted from the pseudocode of various examples of the extended Euclidean algorithm
{
    bnz_t q, rem, tmp1, t, new_t, r, new_r, tmp2;

    bnz_init(&q);
    bnz_init(&rem);
    bnz_init(&t);
    bnz_init(&new_t);
    bnz_init(&r);
    bnz_init(&new_r);
    bnz_init(&tmp1);
    bnz_init(&tmp2);

    bnz_set_i32(&t, 0);
    bnz_set_i32(&new_t, 1);
    bnz_set_bnz(&r, b);
    bnz_set_bnz(&new_r, a);

    while (bnz_is_zero(&new_r) == false) {
        bnz_divide_bnz(&q, &rem, &r, &new_r);
        bnz_set_bnz(&tmp1, &new_t);
        bnz_multiply_bnz(&tmp2, &q, &tmp1);
        bnz_subtract_bnz(&new_t, &t, &tmp2);
        bnz_set_bnz(&t, &tmp1);
        bnz_set_bnz(&tmp1, &new_r);
        bnz_multiply_bnz(&tmp2, &q, &tmp1);
        bnz_subtract_bnz(&new_r, &r, &tmp2);
        bnz_set_bnz(&r, &tmp1);
    }

    if (bnz_cmp_i32(&r, 1) == 1) {
        bnz_set_i32(res, 0);
    } else {
        if (t.sign) bnz_add_bnz(&t, &t, b);
        bnz_set_bnz(res, &t);
    }

    bnz_free(&q);
    bnz_free(&rem);
    bnz_free(&t);
    bnz_free(&new_t);
    bnz_free(&r);
    bnz_free(&new_r);
    bnz_free(&tmp1);
    bnz_free(&tmp2);
}

/* SECP256K1 DEFINES */

typedef struct {
    bnz_t x;
    bnz_t y;
} APT; // standard affine xy point

typedef struct {
    bnz_t x;
    bnz_t y;
    bnz_t z;
} JPT; // extended Jacobian xyz point

typedef struct {
    bnz_t p; // prime
    bnz_t a; // 0
    bnz_t b; // 7
    APT G; // generator point
    APT G_doublings_mod_p[256]; // xy coordinates of 256 consecutive doublings of the secp256k1 generator point mod secp256k1.p i.e. secp256k1.G * 2^n mod secp256k1.p for n = 0 to 255
    bnz_t n; // order
    bnz_t h; // 1
} SECP256K1;

/* SECP256K1 GLOBAL VARIABLES */

uint8_t g_doublings_data[16384] = {152, 23, 248, 22, 91, 129, 242, 89, 217, 40, 206, 45, 219, 252, 155, 2, 7, 11, 135, 206, 149, 98, 160, 85, 172, 187, 220, 249, 126, 102, 190, 121, 184, 212, 16, 251, 143, 208, 71, 156, 25, 84, 133, 166, 72, 180, 23, 253, 168, 8, 17, 14, 252, 251, 164, 93, 101, 196, 163, 38, 119, 218, 58, 72, 229, 158, 112, 92, 185, 9, 172, 171, 167, 60, 239, 140, 75, 142, 119, 92, 216, 124, 192, 149, 110, 64, 69, 48, 109, 125, 237, 65, 148, 127, 4, 198, 42, 229, 207, 80, 169, 49, 100, 35, 225, 208, 102, 50, 101, 50, 246, 247, 238, 234, 108, 70, 25, 132, 197, 163, 57, 195, 61, 166, 254, 104, 225, 26, 19, 205, 196, 232, 171, 148, 250, 116, 132, 117, 224, 14, 144, 19, 108, 204, 4, 20, 11, 147, 4, 73, 30, 88, 243, 128, 13, 193, 241, 219, 147, 228, 34, 153, 115, 71, 220, 123, 233, 207, 64, 254, 189, 191, 51, 174, 103, 217, 72, 20, 165, 142, 9, 226, 66, 86, 183, 85, 212, 160, 62, 153, 237, 81, 1, 42, 10, 225, 243, 78, 120, 103, 138, 136, 175, 229, 5, 221, 27, 10, 47, 60, 15, 183, 63, 132, 243, 175, 29, 53, 202, 92, 225, 229, 1, 47, 4, 233, 189, 108, 183, 44, 218, 181, 23, 118, 91, 186, 214, 19, 226, 194, 180, 19, 45, 19, 42, 8, 61, 41, 73, 153, 83, 65, 167, 168, 77, 92, 10, 236, 109, 42, 158, 232, 78, 196, 233, 90, 122, 184, 105, 19, 163, 178, 151, 62, 194, 33, 188, 170, 17, 48, 197, 158, 158, 181, 147, 206, 15, 230, 33, 104, 97, 105, 206, 44, 243, 225, 11, 63, 210, 68, 30, 137, 150, 18, 16, 55, 121, 245, 52, 159, 185, 157, 146, 149, 229, 153, 115, 80, 227, 247, 101, 62, 20, 7, 212, 219, 208, 117, 29, 166, 4, 153, 184, 252, 207, 218, 206, 120, 243, 226, 84, 224, 182, 71, 45, 162, 181, 79, 215, 153, 1, 211, 185, 106, 16, 36, 31, 255, 179, 5, 150, 129, 237, 100, 195, 12, 118, 31, 101, 128, 131, 233, 201, 222, 214, 179, 195, 213, 227, 10, 157, 141, 3, 149, 139, 239, 116, 248, 230, 24, 121, 227, 129, 253, 186, 205, 29, 111, 76, 252, 60, 130, 50, 248, 234, 81, 16, 11, 183, 234, 22, 45, 84, 193, 35, 191, 159, 29, 131, 102, 254, 126, 195, 77, 120, 47, 30, 129, 84, 252, 34, 197, 228, 146, 83, 186, 160, 40, 217, 122, 115, 3, 48, 195, 111, 134, 179, 92, 78, 162, 105, 103, 69, 119, 112, 100, 85, 86, 83, 0, 215, 92, 245, 188, 28, 103, 209, 247, 9, 61, 108, 105, 6, 122, 63, 3, 228, 59, 255, 52, 26, 47, 204, 115, 122, 6, 145, 132, 129, 182, 248, 232, 195, 22, 223, 85, 140, 9, 50, 152, 216, 25, 102, 63, 85, 108, 35, 58, 98, 17, 157, 93, 8, 21, 245, 213, 63, 226, 70, 6, 161, 28, 172, 213, 171, 156, 195, 216, 56, 226, 45, 23, 62, 110, 42, 234, 217, 9, 198, 18, 50, 38, 130, 130, 175, 108, 226, 246, 175, 110, 27, 211, 190, 23, 123, 47, 172, 19, 214, 98, 206, 10, 182, 48, 232, 86, 130, 94, 228, 223, 87, 133, 9, 168, 248, 17, 77, 162, 52, 239, 0, 44, 110, 146, 208, 89, 225, 217, 104, 201, 219, 10, 213, 24, 249, 156, 122, 133, 90, 144, 243, 159, 167, 135, 178, 112, 83, 70, 244, 135, 56, 179, 32, 251, 248, 162, 16, 122, 211, 21, 178, 9, 142, 88, 193, 194, 238, 253, 218, 139, 175, 164, 130, 192, 104, 131, 179, 49, 229, 53, 31, 19, 133, 226, 178, 1, 185, 213, 136, 176, 19, 200, 205, 110, 236, 170, 64, 98, 173, 102, 143, 161, 100, 214, 119, 189, 60, 226, 184, 235, 31, 36, 109, 2, 80, 39, 111, 230, 179, 171, 175, 181, 12, 189, 15, 253, 80, 205, 248, 29, 152, 19, 189, 32, 196, 214, 211, 248, 148, 255, 217, 120, 51, 81, 113, 4, 146, 155, 6, 99, 203, 237, 13, 222, 35, 244, 133, 139, 49, 252, 217, 248, 216, 131, 41, 204, 228, 252, 121, 250, 114, 161, 78, 219, 27, 93, 3, 49, 184, 247, 102, 6, 51, 112, 123, 110, 197, 150, 153, 30, 235, 121, 86, 38, 162, 56, 148, 185, 75, 121, 46, 158, 55, 121, 103, 130, 67, 40, 57, 183, 229, 81, 181, 229, 252, 115, 237, 34, 34, 253, 51, 56, 185, 224, 109, 132, 252, 198, 198, 156, 249, 114, 90, 134, 139, 114, 159, 21, 94, 23, 149, 214, 254, 233, 254, 111, 250, 110, 92, 52, 36, 221, 90, 149, 181, 172, 94, 31, 247, 31, 165, 151, 239, 164, 235, 121, 60, 158, 13, 110, 80, 211, 214, 71, 188, 70, 158, 4, 120, 206, 27, 18, 218, 198, 181, 254, 253, 48, 33, 198, 57, 225, 200, 188, 255, 165, 215, 50, 255, 3, 63, 1, 58, 66, 52, 138, 84, 139, 109, 110, 35, 209, 158, 0, 79, 82, 195, 142, 13, 114, 199, 179, 246, 186, 123, 159, 23, 161, 112, 217, 225, 225, 15, 224, 26, 185, 74, 130, 22, 132, 247, 246, 45, 48, 65, 39, 62, 59, 47, 102, 223, 73, 118, 135, 214, 188, 122, 122, 144, 8, 5, 185, 31, 172, 69, 106, 29, 17, 208, 233, 8, 33, 212, 17, 161, 169, 76, 202, 218, 150, 137, 0, 112, 240, 82, 89, 6, 255, 219, 72, 13, 185, 251, 175, 142, 71, 28, 145, 150, 6, 117, 215, 206, 27, 224, 221, 94, 171, 86, 78, 247, 94, 138, 182, 144, 114, 255, 220, 185, 188, 190, 93, 121, 173, 184, 200, 199, 122, 201, 109, 74, 74, 109, 214, 141, 167, 104, 143, 191, 178, 172, 66, 71, 66, 219, 12, 233, 29, 87, 244, 192, 57, 247, 249, 62, 148, 114, 30, 99, 22, 176, 17, 153, 82, 64, 70, 255, 131, 143, 173, 107, 82, 254, 47, 85, 85, 126, 28, 68, 83, 224, 46, 38, 182, 5, 172, 206, 153, 156, 12, 176, 71, 212, 144, 61, 54, 233, 157, 238, 59, 127, 60, 0, 98, 203, 158, 25, 8, 144, 168, 185, 69, 49, 54, 243, 151, 83, 68, 59, 149, 33, 34, 115, 252, 173, 115, 226, 4, 65, 197, 146, 175, 92, 42, 113, 210, 157, 181, 223, 46, 1, 251, 98, 11, 191, 2, 59, 201, 198, 115, 57, 85, 155, 126, 154, 237, 102, 152, 27, 76, 32, 224, 143, 198, 253, 243, 196, 114, 173, 177, 62, 228, 215, 234, 82, 198, 156, 230, 86, 206, 83, 183, 188, 127, 15, 138, 190, 32, 211, 146, 247, 193, 209, 243, 170, 190, 140, 242, 200, 224, 53, 241, 40, 26, 188, 237, 51, 50, 78, 181, 128, 7, 60, 47, 154, 82, 43, 177, 131, 186, 119, 56, 8, 164, 185, 84, 178, 240, 77, 83, 43, 177, 144, 239, 209, 110, 87, 231, 1, 32, 226, 179, 97, 147, 214, 131, 191, 184, 121, 188, 239, 254, 18, 246, 233, 64, 58, 211, 64, 121, 90, 219, 211, 140, 185, 3, 66, 69, 10, 136, 13, 110, 111, 200, 86, 47, 26, 62, 78, 58, 181, 192, 140, 210, 65, 198, 4, 168, 122, 150, 70, 109, 250, 149, 206, 67, 169, 54, 247, 156, 168, 140, 241, 26, 232, 71, 96, 193, 66, 40, 236, 61, 208, 166, 47, 43, 37, 131, 190, 149, 12, 248, 253, 223, 85, 154, 247, 105, 27, 205, 91, 161, 129, 167, 228, 67, 136, 99, 69, 183, 181, 68, 98, 140, 190, 194, 243, 93, 22, 95, 75, 139, 54, 253, 212, 95, 198, 240, 239, 179, 86, 238, 98, 97, 84, 54, 227, 249, 4, 218, 176, 58, 129, 215, 251, 179, 180, 8, 211, 104, 111, 10, 173, 74, 190, 228, 85, 71, 113, 38, 63, 187, 122, 153, 124, 65, 238, 100, 175, 113, 16, 97, 60, 200, 126, 124, 225, 140, 113, 145, 50, 225, 228, 92, 12, 237, 47, 244, 123, 160, 110, 250, 249, 99, 177, 218, 61, 118, 37, 57, 217, 73, 128, 166, 126, 90, 127, 173, 61, 191, 189, 69, 35, 188, 199, 159, 26, 34, 171, 200, 206, 7, 200, 230, 182, 212, 206, 82, 5, 110, 86, 84, 50, 229, 232, 250, 241, 131, 63, 92, 177, 179, 148, 230, 76, 196, 19, 176, 236, 250, 112, 80, 21, 171, 217, 223, 129, 137, 46, 46, 94, 184, 134, 178, 50, 156, 61, 177, 47, 236, 198, 2, 46, 252, 87, 203, 158, 14, 233, 181, 9, 204, 247, 177, 209, 154, 174, 78, 246, 7, 62, 205, 35, 79, 130, 221, 178, 179, 253, 202, 203, 55, 11, 26, 115, 200, 242, 210, 202, 45, 19, 138, 187, 9, 128, 28, 129, 195, 39, 6, 19, 100, 83, 45, 117, 244, 64, 168, 84, 15, 133, 62, 134, 79, 40, 221, 249, 182, 185, 227, 238, 175, 178, 178, 91, 148, 218, 252, 50, 82, 146, 21, 97, 203, 123, 231, 192, 166, 255, 219, 0, 183, 199, 72, 213, 11, 192, 113, 247, 107, 109, 153, 219, 229, 166, 186, 60, 114, 95, 159, 179, 158, 157, 6, 220, 1, 72, 73, 121, 55, 101, 160, 96, 38, 110, 77, 130, 136, 116, 19, 33, 169, 152, 196, 92, 89, 181, 103, 232, 150, 213, 48, 160, 12, 214, 131, 211, 31, 7, 73, 152, 7, 67, 10, 36, 45, 198, 163, 115, 87, 196, 125, 61, 52, 77, 116, 123, 67, 134, 167, 239, 87, 158, 47, 176, 116, 66, 180, 122, 176, 74, 151, 233, 229, 42, 109, 155, 104, 236, 3, 222, 40, 201, 39, 54, 137, 24, 133, 180, 209, 11, 219, 18, 215, 213, 77, 88, 12, 119, 199, 175, 127, 42, 1, 123, 50, 126, 87, 128, 16, 185, 108, 34, 213, 156, 126, 223, 162, 66, 188, 40, 106, 67, 189, 75, 38, 17, 171, 4, 119, 147, 39, 18, 230, 141, 141, 123, 113, 67, 130, 17, 106, 34, 190, 51, 76, 226, 92, 247, 212, 180, 147, 224, 78, 169, 111, 124, 216, 232, 56, 36, 75, 216, 107, 242, 43, 157, 236, 189, 213, 31, 198, 139, 167, 157, 167, 54, 98, 5, 92, 200, 218, 187, 210, 64, 189, 36, 101, 76, 169, 244, 97, 134, 241, 219, 200, 226, 194, 43, 155, 227, 160, 96, 60, 93, 126, 58, 158, 1, 5, 149, 33, 121, 253, 128, 98, 249, 146, 217, 31, 32, 181, 250, 215, 125, 14, 202, 62, 83, 154, 131, 25, 169, 55, 18, 150, 71, 9, 181, 211, 194, 18, 200, 238, 95, 186, 152, 191, 190, 147, 212, 164, 191, 238, 153, 137, 222, 225, 218, 79, 253, 221, 18, 247, 17, 167, 195, 205, 228, 154, 157, 8, 120, 241, 218, 126, 238, 105, 242, 240, 14, 151, 163, 140, 154, 93, 253, 151, 210, 71, 8, 233, 190, 118, 214, 102, 103, 143, 192, 75, 234, 196, 95, 73, 24, 193, 49, 96, 28, 166, 253, 123, 169, 167, 215, 74, 28, 56, 197, 63, 73, 125, 24, 227, 172, 147, 0, 156, 147, 219, 50, 16, 69, 240, 204, 94, 145, 9, 167, 95, 62, 143, 228, 238, 142, 35, 59, 245, 106, 147, 76, 69, 222, 46, 66, 112, 141, 68, 178, 8, 221, 239, 95, 208, 241, 156, 71, 140, 83, 217, 49, 8, 225, 204, 59, 198, 173, 5, 205, 185, 239, 225, 151, 55, 145, 168, 51, 210, 159, 173, 198, 212, 162, 167, 68, 50, 78, 70, 35, 113, 71, 254, 31, 76, 21, 176, 231, 155, 175, 216, 48, 69, 203, 14, 164, 153, 235, 41, 179, 238, 63, 211, 24, 123, 212, 51, 159, 65, 229, 199, 168, 117, 244, 154, 94, 35, 172, 197, 16, 112, 105, 162, 177, 249, 24, 83, 45, 249, 145, 254, 238, 110, 114, 44, 101, 236, 227, 209, 64, 43, 31, 164, 232, 5, 180, 235, 58, 217, 114, 87, 25, 164, 237, 75, 235, 207, 76, 244, 176, 141, 164, 57, 91, 131, 215, 239, 191, 3, 60, 155, 162, 21, 18, 159, 69, 222, 123, 155, 160, 208, 145, 39, 103, 113, 110, 105, 218, 68, 15, 16, 9, 90, 198, 43, 214, 92, 189, 15, 172, 149, 81, 255, 24, 74, 255, 183, 102, 6, 9, 12, 48, 243, 200, 46, 119, 11, 160, 146, 49, 225, 217, 205, 6, 247, 77, 30, 79, 40, 5, 75, 8, 8, 125, 35, 249, 200, 217, 216, 153, 65, 76, 43, 255, 93, 65, 168, 113, 199, 181, 206, 242, 137, 9, 140, 152, 250, 114, 93, 163, 197, 106, 115, 170, 17, 101, 21, 245, 107, 222, 96, 108, 150, 220, 185, 44, 23, 210, 255, 52, 32, 67, 79, 4, 189, 77, 251, 253, 191, 71, 220, 51, 60, 230, 177, 27, 188, 149, 188, 57, 133, 82, 156, 37, 192, 98, 50, 116, 129, 164, 196, 4, 103, 38, 94, 60, 21, 143, 251, 149, 176, 73, 217, 221, 69, 10, 9, 19, 38, 84, 172, 137, 19, 222, 29, 83, 205, 188, 180, 217, 17, 250, 22, 24, 98, 224, 197, 157, 122, 162, 108, 154, 98, 178, 75, 139, 27, 250, 184, 184, 167, 55, 119, 88, 44, 160, 101, 132, 112, 40, 167, 240, 201, 12, 90, 117, 81, 93, 215, 63, 51, 71, 231, 214, 246, 70, 105, 26, 150, 141, 159, 154, 150, 26, 110, 170, 118, 131, 200, 129, 37, 76, 128, 3, 54, 196, 76, 17, 12, 7, 69, 1, 254, 175, 242, 45, 253, 52, 229, 230, 205, 138, 44, 133, 179, 243, 100, 68, 141, 127, 167, 23, 192, 4, 74, 122, 34, 201, 29, 27, 237, 199, 98, 226, 27, 3, 225, 13, 160, 86, 148, 242, 24, 79, 164, 121, 237, 28, 158, 65, 221, 146, 242, 90, 83, 151, 101, 23, 164, 182, 107, 94, 64, 64, 137, 146, 97, 112, 157, 86, 131, 92, 169, 54, 126, 226, 132, 87, 216, 148, 222, 197, 106, 138, 2, 201, 178, 41, 15, 205, 93, 249, 185, 234, 137, 128, 76, 34, 63, 185, 244, 211, 31, 0, 190, 185, 97, 88, 189, 154, 96, 21, 73, 52, 241, 126, 195, 144, 238, 14, 164, 167, 246, 229, 176, 223, 98, 41, 6, 236, 146, 122, 166, 138, 14, 22, 123, 225, 47, 214, 32, 108, 105, 126, 249, 18, 133, 30, 213, 176, 8, 91, 2, 234, 34, 150, 177, 54, 82, 229, 252, 161, 172, 209, 9, 68, 76, 160, 124, 197, 80, 224, 52, 229, 181, 18, 146, 238, 224, 233, 111, 126, 194, 216, 224, 44, 105, 86, 62, 198, 240, 1, 81, 143, 24, 83, 17, 194, 127, 186, 117, 4, 125, 125, 233, 98, 149, 195, 191, 147, 58, 139, 81, 231, 205, 33, 56, 121, 173, 162, 24, 158, 43, 76, 69, 204, 89, 108, 198, 86, 89, 95, 247, 156, 198, 195, 126, 151, 85, 89, 177, 221, 96, 10, 240, 178, 12, 193, 170, 206, 243, 164, 190, 207, 15, 179, 191, 226, 47, 89, 217, 109, 105, 148, 144, 141, 104, 94, 45, 245, 106, 29, 164, 102, 178, 248, 92, 236, 215, 59, 20, 159, 131, 194, 10, 83, 91, 213, 70, 174, 108, 234, 254, 136, 0, 9, 24, 191, 222, 85, 49, 45, 68, 65, 204, 87, 137, 28, 152, 92, 205, 62, 191, 18, 78, 110, 176, 186, 225, 220, 151, 108, 107, 124, 229, 8, 43, 117, 238, 10, 4, 164, 10, 135, 161, 49, 179, 224, 202, 30, 20, 121, 225, 178, 157, 175, 97, 50, 197, 225, 135, 219, 26, 98, 11, 0, 77, 234, 44, 48, 72, 31, 133, 114, 62, 58, 41, 199, 25, 241, 245, 125, 203, 204, 114, 217, 130, 85, 130, 109, 203, 85, 210, 224, 24, 143, 91, 13, 106, 239, 88, 92, 71, 253, 98, 153, 248, 119, 27, 31, 62, 64, 160, 87, 214, 40, 113, 113, 20, 33, 38, 170, 214, 93, 160, 61, 32, 202, 112, 245, 113, 14, 66, 93, 211, 114, 154, 100, 248, 125, 62, 54, 195, 0, 93, 68, 242, 141, 91, 201, 91, 52, 87, 85, 210, 13, 136, 220, 149, 91, 65, 66, 235, 89, 131, 255, 67, 96, 176, 72, 96, 81, 118, 94, 198, 29, 130, 180, 70, 20, 160, 29, 194, 181, 130, 210, 183, 83, 210, 123, 159, 98, 179, 183, 162, 194, 254, 134, 254, 236, 127, 57, 162, 53, 56, 111, 4, 53, 8, 209, 16, 201, 41, 30, 247, 163, 55, 169, 87, 45, 18, 149, 22, 148, 56, 48, 105, 177, 108, 236, 193, 139, 151, 250, 51, 222, 131, 133, 128, 125, 101, 237, 254, 60, 202, 255, 230, 75, 190, 103, 179, 220, 156, 4, 145, 29, 169, 103, 218, 29, 190, 104, 122, 226, 168, 158, 126, 161, 64, 247, 8, 197, 173, 199, 222, 229, 128, 151, 236, 247, 99, 244, 65, 188, 66, 22, 72, 53, 170, 172, 155, 201, 65, 231, 31, 130, 204, 227, 94, 131, 90, 234, 204, 53, 159, 189, 139, 113, 216, 0, 175, 250, 12, 12, 124, 88, 239, 161, 95, 54, 205, 186, 77, 35, 182, 142, 51, 248, 16, 190, 96, 95, 83, 192, 159, 160, 132, 195, 12, 157, 41, 56, 232, 89, 253, 220, 127, 46, 137, 81, 138, 14, 84, 195, 22, 218, 24, 226, 180, 186, 168, 237, 135, 80, 96, 104, 82, 241, 133, 76, 15, 89, 194, 65, 255, 216, 23, 143, 230, 238, 155, 80, 129, 196, 255, 209, 19, 25, 28, 25, 219, 157, 65, 219, 224, 39, 209, 91, 109, 32, 1, 173, 164, 189, 88, 183, 177, 55, 147, 203, 206, 29, 150, 145, 169, 31, 57, 8, 96, 184, 109, 233, 162, 202, 64, 59, 19, 255, 219, 41, 206, 22, 217, 201, 60, 59, 83, 176, 69, 156, 199, 89, 118, 0, 96, 108, 239, 156, 79, 155, 33, 199, 107, 59, 141, 167, 1, 223, 39, 101, 87, 144, 62, 197, 138, 79, 57, 110, 42, 55, 192, 128, 65, 164, 245, 234, 239, 89, 217, 5, 198, 217, 36, 192, 183, 55, 26, 204, 92, 84, 87, 159, 6, 17, 187, 247, 208, 8, 236, 81, 33, 242, 94, 147, 0, 224, 166, 221, 76, 51, 11, 170, 79, 144, 83, 200, 113, 39, 2, 107, 9, 203, 157, 105, 52, 68, 225, 129, 153, 153, 19, 28, 60, 13, 194, 202, 236, 201, 136, 109, 16, 128, 188, 208, 135, 192, 91, 169, 124, 164, 56, 31, 15, 205, 87, 173, 133, 15, 173, 170, 231, 110, 42, 93, 153, 22, 99, 25, 145, 249, 60, 117, 70, 65, 157, 175, 117, 165, 1, 183, 205, 235, 119, 46, 223, 197, 103, 166, 126, 77, 159, 93, 60, 185, 189, 152, 134, 187, 225, 82, 252, 85, 204, 195, 13, 178, 138, 203, 241, 56, 48, 91, 86, 21, 227, 85, 215, 9, 227, 110, 12, 194, 211, 131, 26, 166, 211, 214, 85, 97, 183, 193, 245, 113, 202, 57, 212, 33, 118, 67, 224, 240, 245, 130, 204, 46, 221, 175, 48, 132, 103, 10, 228, 215, 62, 191, 97, 191, 165, 26, 16, 247, 13, 22, 137, 33, 246, 43, 5, 90, 190, 98, 78, 159, 107, 51, 45, 54, 245, 217, 129, 231, 203, 66, 118, 34, 70, 33, 201, 203, 71, 227, 164, 12, 151, 109, 243, 167, 87, 154, 110, 11, 108, 11, 111, 80, 143, 63, 36, 250, 135, 12, 125, 72, 48, 175, 142, 187, 67, 93, 146, 207, 72, 104, 51, 28, 79, 66, 197, 48, 149, 113, 97, 250, 42, 93, 149, 159, 70, 71, 96, 216, 58, 244, 89, 249, 239, 202, 139, 155, 58, 4, 58, 181, 121, 103, 144, 202, 100, 119, 202, 156, 113, 167, 131, 89, 211, 11, 205, 123, 142, 42, 55, 96, 132, 126, 4, 16, 234, 179, 104, 253, 71, 46, 142, 232, 121, 69, 81, 169, 12, 66, 16, 3, 148, 179, 164, 61, 42, 11, 119, 183, 16, 81, 3, 63, 241, 139, 128, 210, 119, 231, 137, 3, 61, 141, 91, 193, 59, 223, 80, 105, 153, 25, 243, 80, 195, 157, 114, 94, 25, 170, 91, 179, 51, 24, 116, 141, 203, 204, 3, 197, 43, 112, 155, 136, 188, 239, 96, 101, 170, 188, 82, 141, 36, 54, 64, 70, 249, 135, 191, 10, 100, 133, 1, 138, 165, 54, 187, 20, 68, 178, 199, 29, 215, 166, 188, 215, 202, 9, 225, 246, 86, 34, 126, 31, 7, 210, 58, 184, 92, 149, 63, 201, 34, 174, 238, 77, 55, 74, 115, 175, 141, 169, 190, 117, 120, 33, 67, 229, 0, 99, 214, 40, 56, 41, 247, 6, 248, 6, 44, 3, 22, 153, 79, 205, 79, 182, 101, 17, 23, 22, 214, 231, 106, 173, 100, 138, 94, 12, 159, 42, 182, 242, 186, 77, 148, 220, 176, 174, 149, 115, 224, 70, 124, 229, 234, 58, 127, 156, 192, 128, 35, 26, 188, 27, 22, 72, 190, 153, 0, 86, 103, 132, 143, 20, 146, 175, 147, 154, 176, 9, 213, 239, 138, 89, 241, 106, 149, 100, 52, 25, 134, 142, 111, 98, 56, 196, 153, 21, 30, 132, 10, 105, 230, 151, 131, 241, 244, 167, 113, 222, 27, 184, 137, 134, 129, 208, 230, 33, 255, 205, 193, 52, 237, 94, 56, 83, 84, 46, 84, 229, 143, 69, 192, 140, 220, 134, 32, 236, 78, 48, 107, 87, 244, 235, 233, 25, 222, 1, 103, 245, 35, 234, 232, 195, 235, 59, 40, 124, 130, 242, 120, 112, 162, 131, 220, 226, 28, 252, 190, 66, 38, 200, 71, 209, 103, 95, 77, 19, 190, 86, 4, 128, 84, 175, 61, 8, 34, 246, 246, 2, 161, 170, 32, 181, 32, 91, 209, 246, 27, 50, 72, 116, 202, 87, 230, 231, 206, 103, 179, 21, 87, 44, 175, 15, 58, 231, 125, 129, 78, 205, 27, 182, 220, 90, 113, 9, 50, 137, 157, 54, 111, 140, 125, 206, 195, 145, 205, 85, 194, 31, 61, 60, 203, 112, 189, 226, 61, 149, 143, 24, 229, 38, 251, 243, 104, 186, 88, 59, 202, 219, 73, 84, 171, 183, 184, 49, 203, 210, 22, 105, 23, 208, 25, 167, 70, 232, 88, 77, 163, 18, 16, 129, 40, 225, 243, 30, 140, 120, 96, 117, 219, 68, 237, 215, 209, 139, 14, 6, 55, 140, 209, 183, 234, 60, 118, 188, 198, 245, 40, 45, 19, 185, 17, 89, 34, 145, 137, 241, 14, 143, 142, 34, 66, 92, 99, 17, 158, 239, 253, 132, 156, 150, 54, 250, 54, 177, 89, 53, 118, 184, 39, 155, 172, 201, 124, 152, 77, 139, 218, 167, 195, 250, 195, 134, 237, 6, 198, 201, 251, 71, 89, 74, 248, 221, 15, 24, 250, 61, 65, 164, 115, 124, 99, 145, 241, 236, 3, 184, 217, 249, 6, 96, 33, 132, 58, 96, 144, 104, 216, 2, 16, 40, 92, 47, 221, 164, 126, 212, 196, 69, 14, 163, 226, 184, 105, 186, 89, 48, 96, 142, 198, 128, 124, 45, 215, 127, 75, 116, 34, 157, 92, 23, 218, 228, 167, 229, 69, 23, 218, 57, 41, 72, 132, 194, 54, 220, 28, 28, 65, 43, 37, 234, 238, 134, 174, 188, 56, 238, 78, 122, 203, 52, 35, 40, 247, 114, 20, 85, 17, 146, 141, 233, 240, 159, 88, 206, 10, 171, 98, 249, 2, 115, 112, 201, 147, 233, 25, 144, 146, 22, 124, 38, 116, 20, 122, 238, 242, 54, 207, 117, 190, 24, 135, 72, 44, 220, 86, 140, 47, 29, 230, 85, 255, 191, 11, 249, 201, 72, 34, 87, 162, 62, 136, 18, 138, 157, 54, 226, 43, 218, 53, 2, 117, 99, 225, 24, 186, 53, 180, 85, 187, 6, 165, 215, 238, 33, 45, 105, 148, 5, 250, 227, 100, 9, 181, 75, 172, 13, 253, 118, 111, 28, 221, 119, 8, 159, 169, 208, 133, 64, 217, 72, 27, 193, 74, 7, 68, 92, 224, 22, 110, 26, 225, 200, 191, 130, 6, 139, 191, 127, 118, 111, 140, 49, 56, 225, 198, 173, 23, 36, 175, 240, 150, 37, 94, 173, 225, 48, 212, 162, 135, 91, 6, 214, 135, 189, 230, 208, 66, 231, 224, 183, 19, 83, 94, 15, 219, 99, 209, 116, 247, 203, 110, 77, 16, 124, 20, 162, 130, 37, 78, 60, 36, 1, 212, 34, 51, 160, 178, 40, 108, 233, 162, 243, 36, 246, 58, 135, 162, 62, 246, 5, 40, 183, 249, 218, 77, 188, 25, 176, 191, 245, 78, 102, 233, 151, 7, 231, 86, 98, 228, 173, 192, 50, 109, 105, 252, 41, 207, 219, 234, 200, 221, 76, 13, 213, 12, 200, 4, 27, 243, 14, 18, 174, 189, 206, 80, 2, 32, 38, 141, 12, 71, 38, 15, 185, 168, 224, 216, 58, 139, 103, 114, 78, 251, 74, 29, 186, 54, 238, 195, 45, 111, 31, 211, 55, 244, 91, 113, 180, 59, 237, 235, 51, 230, 22, 21, 62, 100, 100, 145, 139, 156, 45, 7, 13, 147, 212, 142, 59, 208, 148, 245, 161, 104, 64, 206, 169, 190, 174, 110, 118, 192, 56, 18, 5, 120, 123, 199, 40, 183, 205, 5, 40, 2, 116, 204, 45, 37, 70, 9, 23, 220, 195, 209, 226, 121, 201, 214, 89, 19, 39, 187, 45, 176, 157, 138, 102, 122, 142, 120, 82, 21, 176, 25, 22, 194, 14, 43, 40, 215, 220, 205, 185, 17, 106, 138, 117, 234, 178, 231, 21, 156, 203, 112, 7, 91, 29, 39, 39, 151, 60, 224, 88, 114, 141, 122, 78, 130, 138, 80, 227, 101, 160, 226, 127, 135, 172, 73, 153, 208, 87, 228, 145, 244, 231, 52, 88, 164, 58, 93, 131, 171, 52, 129, 210, 116, 29, 114, 151, 51, 100, 247, 154, 63, 27, 116, 104, 88, 102, 137, 13, 119, 209, 43, 218, 183, 224, 45, 125, 44, 103, 133, 166, 19, 3, 121, 79, 9, 227, 200, 68, 143, 41, 197, 252, 23, 127, 231, 229, 194, 98, 250, 155, 4, 116, 99, 235, 178, 67, 91, 155, 27, 72, 124, 37, 252, 23, 31, 188, 144, 139, 153, 150, 109, 46, 223, 70, 234, 137, 59, 31, 166, 200, 21, 18, 134, 193, 54, 192, 158, 15, 116, 107, 207, 76, 83, 118, 110, 232, 207, 110, 127, 28, 215, 221, 40, 221, 191, 119, 210, 227, 10, 85, 67, 213, 50, 221, 227, 42, 70, 219, 45, 139, 156, 176, 92, 113, 213, 182, 232, 190, 232, 35, 9, 23, 199, 210, 200, 251, 236, 71, 13, 2, 121, 237, 170, 248, 24, 32, 20, 30, 8, 243, 183, 135, 238, 92, 31, 29, 169, 193, 68, 6, 65, 170, 22, 61, 0, 37, 178, 140, 98, 159, 86, 0, 248, 178, 211, 218, 221, 200, 137, 113, 90, 225, 142, 223, 226, 78, 50, 138, 116, 116, 207, 132, 89, 37, 28, 26, 170, 16, 31, 246, 190, 69, 174, 53, 7, 60, 56, 212, 226, 221, 20, 162, 193, 53, 142, 12, 217, 35, 140, 92, 193, 0, 176, 204, 57, 216, 140, 164, 196, 162, 21, 176, 80, 45, 119, 191, 71, 186, 215, 95, 226, 69, 111, 220, 200, 53, 34, 82, 40, 216, 84, 169, 43, 10, 42, 200, 96, 175, 89, 217, 255, 50, 136, 102, 15, 198, 38, 146, 15, 177, 19, 148, 145, 241, 201, 6, 107, 164, 136, 25, 155, 128, 191, 72, 9, 137, 229, 200, 216, 136, 127, 203, 212, 190, 210, 124, 201, 8, 255, 77, 109, 140, 65, 195, 209, 197, 116, 107, 220, 70, 102, 203, 109, 133, 98, 165, 83, 10, 0, 139, 126, 69, 176, 110, 57, 81, 94, 130, 30, 51, 193, 22, 239, 182, 240, 145, 98, 198, 228, 92, 13, 54, 89, 46, 55, 127, 44, 149, 38, 90, 112, 239, 5, 31, 64, 61, 140, 49, 103, 61, 101, 143, 57, 190, 222, 34, 132, 104, 45, 61, 137, 188, 98, 136, 166, 0, 88, 76, 234, 19, 245, 150, 79, 19, 118, 137, 88, 2, 241, 233, 176, 214, 114, 101, 25, 33, 245, 67, 242, 31, 19, 139, 190, 242, 190, 189, 197, 35, 252, 230, 88, 46, 198, 126, 249, 76, 209, 212, 126, 39, 130, 62, 28, 115, 99, 53, 133, 251, 188, 197, 31, 20, 83, 103, 103, 61, 140, 103, 161, 177, 69, 125, 130, 151, 67, 187, 140, 24, 11, 128, 248, 134, 54, 151, 222, 7, 8, 32, 3, 28, 184, 176, 34, 102, 113, 154, 50, 131, 22, 116, 92, 236, 14, 82, 96, 116, 16, 36, 33, 39, 31, 54, 182, 215, 1, 166, 61, 206, 141, 116, 13, 46, 36, 17, 74, 245, 156, 155, 107, 50, 53, 140, 89, 33, 154, 192, 212, 229, 171, 232, 216, 143, 243, 25, 216, 236, 204, 42, 117, 105, 252, 77, 228, 176, 241, 168, 115, 40, 240, 224, 124, 6, 79, 195, 1, 24, 70, 127, 206, 96, 98, 23, 174, 180, 178, 149, 78, 168, 193, 152, 193, 81, 128, 35, 146, 210, 236, 247, 30, 106, 119, 73, 144, 240, 167, 113, 181, 165, 111, 43, 168, 45, 188, 45, 124, 71, 61, 111, 116, 102, 7, 126, 210, 170, 150, 81, 92, 230, 22, 19, 26, 79, 232, 155, 64, 200, 222, 115, 26, 173, 72, 71, 218, 216, 133, 112, 221, 209, 199, 111, 129, 121, 32, 166, 213, 196, 51, 32, 160, 176, 148, 188, 199, 239, 49, 101, 83, 107, 88, 144, 102, 92, 102, 83, 139, 148, 88, 217, 128, 11, 108, 45, 49, 80, 72, 240, 71, 220, 15, 16, 126, 30, 77, 238, 227, 62, 204, 233, 146, 8, 140, 150, 75, 236, 231, 102, 113, 42, 142, 80, 159, 178, 214, 42, 31, 198, 73, 154, 52, 6, 215, 136, 182, 151, 82, 72, 157, 106, 113, 155, 210, 237, 44, 89, 190, 44, 174, 169, 11, 219, 234, 190, 97, 69, 44, 61, 250, 33, 153, 15, 217, 89, 19, 232, 178, 74, 238, 80, 137, 143, 215, 236, 102, 131, 220, 142, 245, 191, 66, 88, 199, 155, 118, 95, 104, 217, 176, 255, 11, 146, 213, 173, 115, 120, 123, 118, 119, 161, 65, 71, 93, 63, 247, 206, 228, 220, 200, 186, 131, 231, 47, 54, 23, 248, 75, 45, 250, 55, 32, 141, 204, 83, 41, 67, 220, 191, 117, 245, 200, 62, 4, 3, 65, 191, 75, 65, 72, 131, 61, 212, 216, 193, 175, 224, 125, 3, 229, 218, 91, 117, 29, 132, 220, 229, 224, 16, 31, 72, 236, 3, 91, 95, 189, 221, 11, 153, 251, 9, 141, 249, 249, 181, 211, 148, 170, 75, 83, 113, 69, 239, 52, 61, 158, 199, 200, 99, 140, 219, 45, 42, 121, 124, 33, 171, 195, 62, 27, 214, 210, 247, 108, 11, 244, 148, 84, 253, 103, 164, 13, 224, 165, 76, 219, 122, 47, 206, 197, 85, 184, 172, 0, 9, 121, 254, 220, 96, 91, 210, 67, 191, 153, 254, 38, 23, 66, 85, 133, 96, 229, 245, 229, 143, 9, 82, 18, 185, 215, 96, 113, 115, 230, 42, 87, 119, 68, 46, 253, 74, 109, 196, 251, 155, 28, 187, 244, 25, 53, 64, 43, 58, 239, 245, 21, 148, 169, 100, 194, 237, 75, 172, 119, 163, 115, 221, 77, 15, 89, 173, 22, 154, 137, 182, 246, 246, 36, 15, 241, 226, 185, 75, 248, 129, 174, 76, 230, 208, 130, 23, 15, 84, 106, 182, 101, 196, 216, 43, 19, 12, 95, 112, 13, 117, 76, 248, 53, 249, 152, 224, 221, 142, 125, 252, 209, 79, 158, 159, 78, 111, 181, 45, 16, 0, 2, 174, 252, 162, 70, 84, 168, 204, 203, 99, 41, 212, 33, 29, 45, 88, 240, 173, 17, 220, 211, 86, 168, 204, 41, 52, 229, 232, 50, 37, 231, 252, 228, 10, 106, 134, 37, 183, 197, 166, 198, 209, 219, 232, 231, 180, 113, 23, 143, 94, 144, 234, 245, 173, 7, 162, 244, 176, 114, 99, 224, 221, 49, 238, 78, 249, 52, 112, 178, 112, 72, 16, 135, 119, 74, 72, 215, 140, 72, 90, 173, 178, 123, 162, 18, 254, 140, 225, 188, 116, 137, 144, 122, 62, 255, 210, 62, 228, 174, 9, 254, 60, 237, 198, 78, 219, 191, 94, 4, 60, 63, 173, 79, 48, 189, 141, 156, 143, 107, 4, 162, 76, 19, 172, 14, 136, 9, 33, 125, 32, 6, 114, 225, 118, 19, 242, 183, 150, 246, 25, 172, 153, 23, 177, 242, 59, 16, 191, 69, 66, 155, 53, 121, 190, 13, 99, 73, 220, 164, 191, 223, 228, 6, 103, 71, 23, 91, 200, 4, 120, 138, 148, 245, 31, 180, 219, 122, 157, 17, 146, 131, 25, 234, 31, 115, 144, 133, 120, 214, 6, 84, 59, 189, 107, 205, 123, 202, 124, 160, 201, 221, 196, 241, 6, 98, 170, 19, 28, 210, 198, 245, 14, 148, 196, 99, 80, 157, 200, 168, 234, 40, 179, 249, 143, 228, 64, 251, 117, 114, 26, 176, 153, 85, 32, 166, 177, 199, 75, 29, 183, 18, 15, 33, 191, 74, 151, 64, 160, 217, 203, 252, 48, 105, 78, 106, 233, 142, 95, 171, 221, 207, 26, 197, 172, 228, 19, 155, 15, 9, 120, 109, 95, 135, 219, 252, 48, 218, 234, 1, 71, 185, 148, 174, 2, 127, 84, 151, 85, 208, 8, 105, 173, 64, 133, 245, 163, 226, 221, 11, 177, 4, 34, 224, 12, 220, 249, 187, 208, 88, 83, 212, 213, 92, 113, 122, 60, 33, 242, 88, 180, 52, 117, 194, 242, 223, 237, 126, 106, 243, 245, 80, 72, 187, 144, 161, 91, 36, 6, 173, 19, 112, 80, 98, 228, 90, 11, 173, 109, 75, 172, 127, 200, 14, 94, 137, 147, 137, 240, 124, 46, 98, 116, 185, 26, 13, 14, 72, 35, 131, 237, 159, 174, 102, 127, 154, 180, 50, 129, 84, 94, 28, 239, 212, 194, 95, 61, 123, 93, 85, 76, 50, 254, 38, 235, 172, 222, 163, 211, 42, 76, 29, 250, 89, 185, 43, 143, 70, 127, 131, 15, 246, 252, 79, 188, 29, 83, 212, 161, 203, 15, 226, 112, 201, 213, 254, 25, 28, 144, 31, 206, 199, 187, 16, 66, 233, 246, 222, 141, 102, 197, 2, 6, 109, 39, 70, 226, 184, 134, 150, 9, 48, 135, 175, 153, 188, 225, 255, 251, 173, 139, 73, 153, 237, 13, 87, 135, 34, 41, 74, 184, 117, 76, 212, 36, 127, 15, 14, 29, 0, 47, 82, 19, 239, 20, 97, 153, 216, 120, 220, 172, 224, 80, 104, 99, 145, 49, 28, 33, 235, 101, 78, 79, 194, 166, 167, 236, 104, 234, 239, 21, 68, 188, 115, 159, 65, 40, 193, 113, 135, 132, 179, 159, 149, 19, 228, 23, 154, 113, 163, 7, 3, 21, 218, 20, 60, 88, 157, 134, 71, 184, 170, 60, 213, 251, 8, 59, 58, 204, 240, 221, 44, 198, 173, 112, 140, 131, 226, 135, 154, 65, 165, 82, 147, 187, 141, 78, 179, 244, 122, 42, 39, 124, 78, 230, 170, 220, 23, 24, 148, 179, 224, 51, 221, 247, 191, 20, 150, 11, 83, 27, 104, 239, 109, 159, 208, 111, 225, 24, 11, 157, 108, 118, 156, 116, 23, 77, 27, 110, 124, 110, 30, 130, 226, 144, 135, 239, 27, 90, 242, 17, 155, 156, 93, 56, 78, 159, 38, 138, 38, 143, 136, 150, 38, 176, 23, 144, 137, 43, 171, 20, 216, 218, 235, 154, 0, 18, 178, 50, 249, 192, 27, 229, 228, 250, 139, 53, 54, 131, 121, 69, 187, 240, 52, 179, 181, 218, 44, 174, 67, 47, 113, 95, 126, 161, 53, 38, 175, 168, 131, 181, 145, 191, 245, 49, 40, 14, 127, 34, 99, 142, 114, 244, 168, 212, 95, 144, 110, 247, 68, 246, 103, 229, 96, 113, 112, 94, 203, 138, 214, 152, 97, 211, 247, 136, 20, 14, 94, 120, 207, 134, 181, 183, 222, 90, 240, 4, 93, 68, 102, 143, 214, 51, 184, 98, 167, 137, 59, 237, 99, 2, 193, 141, 107, 238, 18, 48, 201, 13, 147, 18, 71, 139, 150, 84, 160, 128, 250, 85, 37, 101, 147, 108, 135, 127, 50, 1, 51, 32, 185, 89, 217, 159, 156, 254, 125, 189, 254, 112, 80, 83, 117, 185, 151, 25, 94, 37, 105, 153, 176, 38, 64, 82, 179, 234, 4, 212, 178, 182, 39, 251, 64, 40, 126, 66, 50, 118, 5, 67, 190, 178, 61, 110, 199, 165, 106, 104, 97, 173, 56, 242, 16, 27, 139, 119, 190, 61, 78, 167, 254, 111, 185, 60, 242, 183, 61, 29, 112, 119, 123, 63, 151, 107, 89, 107, 18, 147, 175, 182, 204, 222, 116, 246, 124, 41, 19, 11, 155, 219, 104, 5, 110, 228, 86, 151, 31, 150, 124, 217, 143, 72, 48, 55, 222, 229, 14, 87, 187, 14, 205, 232, 80, 216, 3, 14, 24, 255, 128, 66, 48, 200, 65, 148, 237, 174, 191, 58, 63, 249, 9, 14, 255, 139, 233, 77, 254, 116, 55, 242, 9, 30, 145, 19, 139, 18, 118, 161, 175, 25, 250, 139, 254, 158, 158, 190, 61, 25, 241, 28, 213, 51, 208, 186, 21, 48, 77, 171, 79, 216, 189, 16, 91, 81, 135, 180, 36, 246, 211, 254, 201, 63, 124, 122, 230, 142, 105, 217, 41, 57, 99, 5, 117, 5, 116, 136, 60, 150, 194, 167, 147, 14, 148, 156, 184, 111, 201, 241, 4, 84, 18, 122, 39, 69, 43, 200, 125, 81, 44, 208, 127, 145, 36, 66, 127, 83, 68, 124, 70, 255, 12, 6, 134, 74, 62, 69, 253, 49, 10, 88, 51, 189, 183, 63, 111, 109, 147, 19, 80, 208, 87, 107, 18, 132, 239, 163, 157, 25, 31, 163, 175, 71, 147, 243, 11, 195, 186, 72, 225, 176, 63, 191, 162, 235, 163, 196, 227, 194, 98, 22, 6, 19, 220, 167, 193, 57, 222, 189, 23, 68, 42, 192, 82, 41, 67, 96, 183, 121, 225, 68, 21, 211, 104, 153, 89, 13, 87, 162, 16, 14, 207, 119, 246, 19, 65, 230, 118, 1, 172, 1, 25, 45, 117, 177, 180, 50, 32, 109, 181, 210, 51, 42, 94, 211, 240, 129, 6, 215, 102, 112, 87, 207, 149, 78, 238, 141, 223, 13, 201, 165, 135, 17, 58, 168, 153, 249, 28, 105, 174, 41, 44, 98, 87, 93, 0, 16, 200, 97, 129, 216, 201, 135, 238, 59, 199, 82, 158, 14, 83, 138, 112, 192, 185, 61, 71, 155, 241, 164, 88, 138, 62, 53, 109, 60, 167, 205, 62, 40, 56, 109, 187, 220, 86, 150, 250, 151, 168, 249, 225, 17, 72, 136, 155, 190, 245, 228, 205, 198, 22, 27, 46, 158, 181, 178, 134, 109, 75, 55, 159, 207, 98, 228, 149, 131, 100, 189, 25, 226, 59, 139, 196, 79, 3, 207, 25, 242, 26, 50, 111, 43, 83, 145, 10, 12, 28, 15, 63, 201, 209, 145, 239, 71, 25, 24, 171, 104, 190, 180, 195, 102, 180, 90, 161, 6, 43, 227, 40, 232, 243, 124, 209, 9, 194, 171, 227, 25, 34, 234, 75, 3, 189, 147, 238, 118, 245, 151, 131, 47, 156, 113, 124, 13, 95, 203, 120, 160, 68, 108, 175, 234, 186, 81, 23, 96, 208, 173, 184, 53, 212, 160, 124, 234, 42, 54, 236, 223, 70, 178, 60, 21, 115, 158, 175, 48, 75, 93, 232, 111, 9, 132, 7, 145, 184, 203, 43, 36, 80, 177, 58, 238, 203, 38, 223, 67, 198, 124, 143, 154, 143, 63, 116, 170, 27, 40, 232, 225, 171, 178, 3, 107, 197, 56, 199, 195, 132, 154, 105, 217, 53, 231, 23, 233, 207, 128, 120, 239, 78, 49, 130, 187, 187, 191, 172, 46, 143, 113, 127, 83, 210, 26, 149, 120, 181, 63, 137, 27, 171, 98, 70, 120, 176, 170, 221, 228, 201, 184, 73, 234, 151, 113, 100, 148, 170, 231, 146, 105, 42, 179, 53, 116, 3, 124, 205, 94, 132, 120, 85, 17, 53, 111, 5, 243, 24, 109, 49, 222, 100, 93, 106, 116, 167, 83, 246, 83, 64, 42, 29, 165, 208, 166, 206, 195, 226, 109, 139, 151, 7, 29, 230, 41, 108, 139, 148, 184, 105, 248, 148, 96, 153, 227, 252, 84, 35, 241, 34, 205, 236, 12, 29, 188, 163, 191, 74, 204, 100, 163, 136, 56, 56, 243, 71, 249, 126, 83, 14, 18, 225, 222, 30, 168, 148, 249, 136, 149, 73, 187, 24, 113, 108, 65, 91, 103, 72, 14, 25, 55, 41, 3, 15, 141, 154, 202, 72, 219, 74, 255, 5, 143, 108, 26, 168, 104, 247, 190, 252, 214, 112, 245, 20, 246, 213, 165, 198, 201, 180, 102, 228, 207, 184, 65, 174, 52, 31, 192, 192, 101, 16, 53, 172, 115, 255, 78, 252, 133, 91, 209, 112, 209, 67, 188, 205, 206, 184, 117, 64, 11, 122, 147, 124, 92, 127, 53, 228, 190, 245, 132, 11, 75, 193, 246, 136, 101, 159, 46, 55, 20, 80, 146, 58, 95, 46, 215, 209, 119, 40, 151, 124, 99, 199, 100, 226, 129, 91, 182, 72, 101, 98, 149, 216, 31, 153, 125, 93, 215, 62, 54, 121, 225, 103, 176, 43, 99, 141, 66, 3, 235, 64, 195, 24, 8, 198, 142, 114, 174, 126, 188, 242, 56, 170, 191, 254, 36, 132, 7, 119, 75, 89, 91, 186, 63, 12, 196, 14, 122, 175, 236, 3, 103, 162, 3, 32, 98, 67, 58, 138, 78, 4, 113, 137, 239, 110, 19, 253, 241, 221, 113, 198, 239, 238, 97, 205, 168, 223, 42, 138, 247, 177, 242, 124, 165, 239, 197, 181, 145, 209, 161, 103, 204, 82, 198, 243, 52, 168, 141, 33, 60, 203, 177, 141, 236, 132, 29, 95, 74, 2, 63, 212, 160, 3, 112, 27, 134, 159, 81, 103, 83, 202, 156, 14, 20, 141, 99, 217, 157, 142, 158, 217, 167, 55, 134, 107, 227, 41, 138, 216, 92, 118, 200, 255, 248, 254, 134, 98, 110, 186, 206, 27, 50, 187, 69, 169, 167, 163, 192, 28, 173, 25, 220, 54, 114, 81, 56, 60, 141, 246, 70, 253, 54, 230, 64, 4, 30, 53, 3, 210, 145, 145, 176, 229, 84, 138, 189, 161, 23, 131, 25, 154, 97, 241, 253, 3, 148, 151, 203, 252, 240, 103, 172, 121, 43, 35, 231, 144, 158, 146, 155, 91, 117, 115, 133, 60, 125, 12, 71, 254, 195, 18, 92, 110, 192, 2, 141, 64, 3, 110, 103, 79, 86, 10, 21, 73, 221, 78, 232, 147, 54, 199, 255, 206, 97, 135, 30, 87, 51, 100, 15, 235, 24, 117, 149, 42, 3, 148, 218, 184, 231, 246, 253, 78, 231, 228, 136, 20, 81, 59, 255, 149, 77, 88, 204, 146, 176, 8, 40, 118, 201, 156, 201, 215, 228, 161, 5, 72, 164, 223, 4, 40, 106, 114, 175, 197, 20, 244, 19, 212, 230, 246, 91, 178, 92, 62, 154, 70, 249, 32, 182, 138, 105, 203, 242, 83, 206, 197, 140, 237, 5, 209, 54, 109, 125, 252, 249, 19, 26, 73, 112, 197, 53, 138, 16, 180, 54, 153, 197, 220, 41, 0, 197, 149, 108, 198, 216, 114, 158, 102, 119, 227, 52, 92, 186, 228, 153, 219, 64, 165, 12, 163, 226, 134, 34, 129, 75, 83, 192, 9, 19, 235, 227, 176, 240, 102, 250, 131, 104, 208, 12, 172, 211, 12, 225, 189, 182, 58, 163, 120, 218, 27, 227, 63, 135, 230, 67, 192, 105, 227, 176, 55, 209, 56, 156, 233, 19, 106, 169, 23, 49, 252, 215, 113, 232, 155, 7, 98, 202, 186, 218, 72, 16, 159, 39, 191, 119, 119, 186, 211, 221, 115, 243, 212, 47, 186, 226, 188, 7, 157, 157, 6, 186, 253, 240, 86, 173, 241, 227, 52, 102, 121, 1, 207, 6, 161, 36, 190, 249, 232, 98, 72, 215, 207, 216, 118, 37, 83, 242, 39, 121, 90, 115, 116, 222, 86, 137, 11, 178, 207, 182, 226, 142, 77, 93, 223, 192, 227, 120, 23, 161, 241, 146, 167, 86, 81, 251, 239, 25, 32, 171, 127, 93, 71, 185, 218, 138, 125, 58, 179, 31, 68, 20, 234, 15, 232, 120, 236, 201, 106, 27, 41, 180, 252, 169, 46, 50, 175, 128, 94, 21, 45, 71, 148, 202, 163, 140, 118, 137, 30, 119, 0, 142, 99, 127, 222, 209, 238, 88, 205, 131, 15, 139, 231, 176, 45, 22, 249, 210, 119, 56, 204, 45, 18, 55, 122, 254, 30, 237, 196, 26, 152, 101, 18, 164, 142, 240, 161, 12, 68, 75, 63, 138, 184, 105, 192, 123, 176, 96, 162, 192, 105, 66, 77, 30, 162, 2, 47, 78, 157, 220, 84, 137, 175, 34, 225, 94, 205, 210, 176, 200, 166, 16, 139, 153, 18, 39, 218, 27, 232, 217, 41, 178, 193, 188, 14, 199, 155, 129, 7, 169, 211, 41, 248, 247, 197, 28, 108, 150, 43, 175, 203, 148, 246, 81, 94, 240, 0, 23, 139, 120, 246, 71, 42, 60, 24, 195, 100, 108, 235, 42, 216, 70, 204, 250, 95, 60, 99, 61, 240, 190, 97, 186, 62, 166, 64, 253, 83, 213, 141, 53, 19, 90, 249, 20, 100, 139, 192, 149, 246, 171, 71, 80, 89, 162, 57, 244, 212, 182, 80, 72, 104, 86, 53, 42, 134, 110, 139, 237, 229, 155, 62, 211, 218, 3, 216, 208, 131, 51, 24, 90, 60, 172, 36, 161, 159, 235, 244, 45, 188, 16, 13, 180, 28, 209, 14, 145, 8, 94, 234, 112, 96, 225, 196, 188, 123, 192, 221, 21, 105, 253, 30, 3, 130, 161, 242, 67, 117, 86, 29, 229, 72, 186, 19, 67, 112, 205, 223, 123, 105, 1, 163, 161, 126, 23, 30, 4, 26, 13, 12, 19, 26, 161, 192, 247, 219, 53, 23, 155, 15, 212, 37, 250, 9, 24, 8, 245, 228, 103, 251, 28, 249, 112, 115, 174, 165, 75, 242, 22, 3, 66, 17, 216, 181, 52, 76, 0, 101, 57, 180, 116, 255, 11, 158, 65, 210, 232, 243, 73, 240, 121, 255, 156, 229, 225, 39, 179, 69, 58, 136, 238, 191, 165, 132, 247, 99, 250, 154, 166, 161, 72, 223, 5, 223, 121, 252, 60, 94, 27, 238, 9, 226, 4, 200, 166, 38, 11, 49, 174, 215, 174, 156, 92, 23, 105, 153, 79, 251, 251, 132, 222, 173, 57, 90, 79, 126, 45, 137, 195, 142, 88, 22, 238, 74, 134, 246, 165, 231, 18, 199, 148, 98, 21, 70, 170, 72, 209, 132, 55, 230, 12, 75, 84, 142, 13, 56, 229, 217, 29, 49, 130, 75, 237, 101, 179, 99, 99, 81, 7, 65, 100, 73, 3, 219, 166, 68, 254, 225, 67, 27, 121, 93, 39, 88, 111, 93, 200, 178, 252, 117, 134, 107, 66, 13, 92, 6, 93, 35, 179, 164, 4, 5, 252, 11, 66, 133, 75, 70, 26, 141, 172, 88, 5, 79, 93, 52, 151, 113, 66, 55, 146, 201, 166, 148, 127, 236, 184, 63, 69, 243, 52, 108, 122, 70, 85, 25, 212, 78, 176, 63, 62, 198, 122, 171, 255, 127, 48, 17, 11, 51, 204, 8, 226, 141, 103, 18, 5, 157, 63, 70, 54, 185, 214, 137, 179, 133, 173, 144, 80, 241, 110, 203, 72, 77, 29, 153, 77, 137, 130, 21, 190, 250, 174, 57, 184, 34, 114, 66, 217, 203, 253, 175, 97, 130, 163, 32, 54, 122, 80, 14, 81, 1, 220, 167, 237, 176, 24, 40, 173, 123, 112, 70, 230, 91, 18, 126, 61, 94, 66, 72, 21, 29, 75, 244, 119, 64, 201, 248, 14, 212, 44, 126, 199, 30, 114, 32, 57, 197, 59, 154, 44, 8, 238, 174, 64, 238, 155, 136, 93, 249, 30, 50, 139, 26, 166, 130, 179, 250, 220, 42, 8, 117, 91, 144, 151, 229, 69, 19, 228, 58, 16, 14, 249, 60, 133, 219, 249, 107, 99, 156, 167, 82, 239, 209, 187, 117, 201, 33, 206, 218, 190, 149, 33, 245, 70, 161, 10, 119, 90, 244, 106, 103, 117, 118, 176, 148, 240, 33, 178, 165, 103, 234, 64, 27, 179, 219, 210, 93, 233, 154, 176, 254, 83, 176, 10, 155, 169, 165, 68, 84, 228, 76, 252, 83, 187, 12, 226, 196, 204, 254, 30, 66, 222, 219, 20, 129, 90, 178, 218, 249, 251, 188, 185, 147, 25, 207, 161, 117, 76, 210, 87, 74, 221, 135, 105, 36, 147, 203, 36, 229, 241, 153, 244, 147, 117, 191, 138, 167, 229, 16, 24, 125, 203, 207, 209, 193, 77, 232, 45, 29, 254, 88, 218, 192, 196, 158, 76, 68, 123, 27, 53, 163, 62, 114, 120, 86, 140, 232, 46, 22, 31, 152, 173, 193, 57, 146, 51, 95, 59, 246, 210, 185, 104, 143, 130, 255, 31, 80, 121, 191, 60, 242, 253, 11, 81, 149, 254, 44, 234, 187, 93, 33, 190, 182, 194, 144, 29, 222, 134, 57, 6, 186, 45, 159, 42, 102, 118, 112, 242, 76, 248, 125, 132, 230, 174, 126, 98, 231, 173, 88, 152, 216, 89, 175, 217, 127, 231, 235, 175, 252, 88, 129, 78, 120, 253, 174, 73, 77, 30, 120, 170, 3, 98, 182, 144, 107, 70, 216, 244, 125, 26, 45, 15, 110, 240, 166, 156, 53, 16, 242, 35, 231, 53, 209, 13, 161, 89, 252, 50, 205, 38, 32, 182, 41, 87, 203, 219, 232, 78, 29, 157, 136, 224, 61, 42, 141, 167, 90, 92, 31, 158, 97, 214, 55, 133, 111, 213, 133, 158, 83, 100, 117, 243, 12, 206, 218, 250, 200, 114, 65, 51, 159, 183, 84, 217, 172, 74, 104, 37, 41, 114, 74, 82, 223, 49, 82, 198, 179, 73, 55, 65, 133, 214, 193, 120, 162, 180, 87, 205, 218, 100, 83, 43, 8, 244, 31, 95, 26, 246, 120, 200, 204, 217, 26, 48, 255, 70, 103, 121, 39, 223, 217, 122, 145, 10, 33, 49, 34, 123, 12, 253, 19, 39, 127, 252, 11, 242, 175, 26, 230, 137, 55, 125, 115, 214, 248, 129, 190, 57, 122, 123, 229, 181, 80, 84, 27, 14, 103, 17, 30, 35, 83, 80, 253, 134, 102, 62, 30, 104, 3, 101, 232, 72, 31, 9, 54, 140, 25, 249, 159, 249, 95, 214, 133, 175, 118, 1, 251, 243, 228, 188, 115, 235, 111, 87, 56, 44, 130, 201, 209, 81, 201, 78, 231, 199, 108, 40, 183, 2, 234, 208, 166, 97, 22, 28, 79, 239, 208, 58, 99, 99, 30, 47, 175, 205, 59, 35, 226, 254, 59, 149, 114, 161, 91, 130, 26, 83, 136, 47, 54, 219, 171, 16, 65, 198, 30, 224, 115, 103, 104, 183, 203, 48, 75, 183, 181, 38, 61, 70, 61, 3, 104, 117, 133, 52, 228, 129, 60, 223, 31, 169, 196, 195, 119, 87, 44, 158, 111, 155, 98, 187, 101, 2, 53, 198, 116, 159, 5, 115, 166, 41, 156, 254, 47, 25, 250, 224, 80, 80, 113, 17, 236, 23, 72, 70, 23, 11, 178, 21, 205, 13, 112, 225, 122, 170, 52, 180, 203, 12, 7, 124, 34, 66, 150, 218, 183, 69, 248, 213, 10, 79, 94, 212, 65, 173, 223, 181, 56, 35, 73, 45, 86, 23, 189, 218, 180, 10, 32, 26, 74, 192, 18, 222, 6, 225, 134, 71, 77, 233, 16, 70, 135, 197, 218, 156, 109, 76, 36, 87, 117, 30, 123, 109, 208, 28, 44, 16, 156, 109, 5, 120, 244, 254, 97, 83, 202, 230, 108, 167, 105, 215, 146, 171, 9, 246, 126, 193, 38, 76, 105, 104, 16, 224, 149, 128, 230, 70, 57, 62, 243, 16, 230, 9, 127, 158, 226, 234, 32, 174, 110, 251, 22, 7, 29, 78, 13, 47, 79, 3, 199, 102, 66, 90, 164, 55, 21, 150, 235, 49, 243, 235, 24, 155, 250, 0, 140, 75, 65, 2, 103, 198, 164, 210, 231, 84, 108, 227, 129, 250, 218, 250, 194, 116, 201, 54, 55, 58, 52, 220, 169, 161, 33, 165, 254, 103, 114, 164, 239, 95, 218, 138, 193, 176, 154, 76, 232, 179, 47, 18, 41, 127, 41, 126, 253, 239, 225, 107, 99, 249, 91, 187, 168, 111, 180, 162, 109, 23, 192, 207, 36, 107, 88, 138, 151, 57, 97, 250, 104, 242, 20, 248, 164, 161, 156, 149, 237, 39, 169, 237, 93, 77, 113, 104, 152, 166, 97, 156, 7, 187, 143, 255, 235, 162, 157, 103, 148, 149, 24, 3, 241, 237, 87, 240, 199, 127, 214, 221, 22, 198, 46, 41, 161, 114, 237, 45, 234, 130, 188, 185, 212, 88, 125, 74, 0, 38, 254, 159, 119, 132, 244, 119, 72, 138, 162, 63, 150, 148, 180, 195, 113, 59, 27, 199, 126, 20, 216, 177, 230, 117, 203, 2, 103, 183, 197, 138, 185, 101, 75, 124, 200, 173, 78, 243, 204, 169, 178, 7, 30, 138, 128, 248, 150, 73, 206, 102, 192, 226, 197, 118, 252, 199, 1, 208, 203, 196, 105, 125, 238, 90, 169, 54, 209, 78, 244, 232, 35, 229, 66, 233, 186, 153, 137, 62, 195, 226, 46, 15, 3, 191, 42, 25, 26, 130, 19, 164, 193, 110, 98, 200, 236, 65, 62, 203, 96, 252, 221, 127, 153, 192, 146, 139, 48, 79, 8, 61, 20, 211, 142, 233, 169, 192, 206, 16, 62, 159, 130, 212, 157, 230, 108, 162, 231, 81, 253, 44, 207, 33, 148, 138, 14, 226, 131, 14, 66, 192, 178, 166, 208, 24, 187, 175, 26, 106, 0, 27, 71, 75, 152, 167, 15, 48, 142, 117, 42, 97, 232, 74, 123, 145, 91, 126, 217, 169, 47, 227, 214, 228, 53, 60, 32, 245, 137, 32, 119, 182, 191, 56, 13, 208, 248, 107, 3, 186, 250, 202, 245, 156, 35, 130, 13, 156, 35, 156, 204, 243, 5, 47, 85, 156, 42, 59, 155, 21, 57, 8, 100, 4, 153, 255, 123, 129, 109, 42, 2, 138, 59, 232, 25, 81, 150, 42, 189, 215, 76, 253, 132, 32, 152, 76, 73, 156, 80, 158, 143, 66, 5, 232, 215, 86, 81, 223, 18, 31, 63, 182, 206, 36, 144, 56, 233, 36, 104, 120, 94, 183, 226, 253, 254, 254, 11, 119, 198, 206, 16, 113, 141, 241, 170, 113, 246, 186, 122, 40, 249, 149, 101, 114, 35, 135, 104, 72, 134, 139, 171, 221, 124, 174, 65, 45, 207, 111, 142, 198, 83, 18, 77, 14, 159, 55, 12, 45, 216, 0, 105, 17, 237, 107, 37, 41, 120, 216, 89, 69, 38, 115, 228, 29, 0, 69, 75, 246, 201, 230, 241, 202, 57, 175, 49, 134, 122, 215, 114, 64, 3, 55, 198, 123, 239, 44, 81, 211, 38, 25, 189, 229, 121, 239, 128, 107, 222, 179, 158, 242, 60, 79, 66, 121, 125, 150, 203, 203, 113, 197, 189, 188, 35, 194, 64, 53, 210, 200, 46, 102, 227, 14, 158, 69, 182, 69, 186, 113, 26, 182, 240, 11, 243, 47, 91, 227, 72, 109, 174, 179, 196, 179, 29, 102, 229, 22, 223, 218, 225, 109, 224, 243, 6, 109, 135, 124, 6, 31, 181, 62, 3, 117, 243, 62, 37, 17, 194, 121, 190, 118, 5, 137, 182, 147, 21, 244, 1, 115, 111, 211, 228, 136, 60, 130, 217, 240, 232, 216, 229, 217, 162, 98, 90, 150, 189, 213, 121, 73, 245, 240, 217, 70, 220, 9, 229, 240, 238, 254, 216, 87, 106, 177, 171, 4, 62, 30, 134, 183, 233, 193, 77, 100, 94, 21, 15, 72, 118, 166, 55, 23, 1, 163, 168, 79, 190, 102, 171, 221, 224, 186, 33, 115, 15, 107, 197, 61, 140, 188, 125, 247, 39, 202, 169, 151, 50, 27, 86, 60, 51, 63, 31, 174, 240, 202, 27, 130, 65, 93, 135, 4, 208, 2, 108, 36, 210, 151, 209, 212, 20, 251, 120, 86, 51, 187, 244, 124, 36, 238, 214, 41, 198, 75, 109, 224, 206, 81, 127, 132, 142, 71, 31, 89, 231, 207, 17, 86, 16, 186, 94, 242, 215, 134, 6, 128, 113, 251, 104, 93, 134, 1, 26, 45, 130, 31, 174, 157, 60, 199, 4, 11, 88, 141, 154, 7, 12, 27, 80, 39, 84, 115, 115, 54, 150, 221, 98, 52, 210, 18, 205, 232, 67, 105, 73, 91, 15, 218, 222, 165, 197, 115, 126, 198, 31, 111, 29, 35, 6, 143, 17, 170, 52, 50, 121, 64, 184, 11, 40, 200, 128, 138, 214, 32, 49, 19, 107, 38, 132, 76, 41, 90, 41, 69, 120, 143, 123, 14, 91, 139, 226, 176, 119, 145, 31, 75, 12, 208, 134, 181, 244, 255, 169, 139, 219, 253, 182, 18, 164, 44, 34, 218, 139, 130, 43, 112, 111, 60, 5, 237, 172, 60, 55, 82, 55, 251, 142, 47, 64, 190, 64, 122, 103, 156, 64, 106, 241, 218, 82, 160, 236, 119, 174, 141, 38, 164, 188, 158, 36, 89, 6, 84, 22, 78, 14, 227, 116, 90, 167, 166, 215, 153, 39, 83, 20, 23, 49, 65, 42, 228, 212, 109, 50, 110, 11, 26, 92, 50, 152, 237, 107, 47, 79, 159, 184, 77, 248, 118, 153, 105, 127, 227, 251, 66, 111, 118, 171, 6, 181, 84, 65, 28, 237, 93, 7, 149, 146, 133, 108, 212, 45, 226, 209, 217, 169, 78, 65, 246, 95, 2, 97, 77, 228, 198, 148, 136, 152, 197, 67, 80, 7, 173, 35, 70, 2, 127, 63, 166, 167, 81, 76, 223, 125, 114, 252, 73, 110, 232, 147, 234, 86, 89, 11, 77, 141, 10, 8, 193, 149, 204, 105, 39, 101, 60, 183, 123, 64, 42, 234, 100, 81, 126, 89, 229, 84, 229, 198, 228, 114, 13, 26, 234, 193, 182, 197, 147, 88, 83, 75, 157, 202, 116, 113, 16, 219, 103, 154, 93, 61, 141, 194, 15, 152, 149, 64, 234, 156, 68, 115, 185, 174, 18, 150, 176, 48, 122, 144, 112, 2, 220, 82, 66, 128, 92, 246, 125, 237, 74, 50, 132, 124, 171, 150, 175, 36, 114, 150, 67, 40, 51, 126, 12, 59, 33, 25, 79, 31, 236, 90, 195, 192, 48, 241, 47, 31, 182, 116, 87, 54, 138, 100, 73, 151, 145, 178, 129, 131, 243, 168, 31, 219, 224, 141, 74, 62, 43, 247, 3, 114, 13, 136, 129, 38, 211, 40, 2, 73, 111, 162, 30, 51, 201, 50, 227, 181, 144, 242, 176, 151, 30, 99, 9, 171, 57, 174, 189, 74, 138, 38, 184, 219, 243, 182, 2, 47, 90, 105, 181, 156, 32, 52, 43, 39, 205, 215, 228, 149, 151, 123, 82, 34, 28, 30, 142, 107, 132, 225, 182, 97, 193, 105, 28, 107, 236, 15, 167, 246, 2, 74, 133, 55, 152, 59, 59, 47, 41, 235, 254, 160, 83, 174, 47, 157, 126, 91, 111, 28, 17, 9, 117, 29, 19, 87, 91, 131, 69, 241, 74, 99, 150, 22, 128, 190, 238, 150, 90, 194, 67, 140, 221, 63, 48, 137, 87, 157, 163, 174, 53, 237, 209, 25, 127, 69, 113, 77, 225, 251, 73, 0, 49, 212, 32, 230, 242, 94, 59, 223, 1, 58, 90, 166, 3, 135, 230, 2, 141, 74, 212, 218, 202, 211, 174, 79, 2, 29, 134, 134, 118, 44, 237, 144, 141, 61, 244, 184, 111, 92, 255, 12, 148, 160, 142, 121, 150, 76, 5, 253, 115, 211, 139, 142, 136, 202, 209, 168, 59, 20, 196, 238, 220, 229, 254, 229, 219, 223, 81, 109, 31, 230, 205, 25, 73, 193, 249, 77, 93, 13, 209, 202, 6, 172, 235, 146, 1, 73, 136, 194, 205, 6, 213, 181, 212, 133, 29, 58, 194, 116, 9, 5, 40, 135, 45, 9, 81, 236, 53, 0, 4, 158, 164, 29, 252, 176, 198, 192, 112, 141, 122, 229, 84, 69, 222, 233, 136, 112, 184, 228, 212, 23, 83, 210, 140, 153, 204, 210, 216, 202, 50, 237, 224, 185, 29, 124, 209, 32, 49, 182, 125, 171, 159, 180, 172, 159, 218, 82, 11, 210, 89, 88, 55, 202, 65, 165, 4, 2, 3, 29, 95, 239, 159, 18, 85, 248, 131, 232, 212, 24, 116, 203, 22, 64, 195, 99, 203, 109, 195, 40, 110, 54, 112, 28, 17, 228, 73, 128, 241, 96, 99, 77, 114, 171, 33, 232, 223, 45, 133, 89, 106, 12, 78, 237, 239, 35, 236, 20, 198, 25, 59, 139, 89, 207, 22, 84, 17, 212, 208, 103, 227, 60, 245, 99, 248, 203, 239, 173, 46, 116, 65, 180, 238, 89, 255, 251, 233, 6, 56, 175, 71, 165, 20, 47, 167, 147, 150, 188, 47, 69, 85, 244, 18, 210, 26, 229, 148, 137, 13, 63, 190, 173, 236, 207, 59, 54, 101, 140, 149, 61, 209, 58, 44, 94, 32, 30, 11, 110, 122, 132, 14, 203, 229, 69, 196, 61, 140, 242, 35, 108, 215, 251, 205, 152, 31, 172, 200, 153, 252, 203, 8, 3, 127, 77, 5, 137, 52, 82, 33, 96, 198, 28, 156, 138, 237, 250, 112, 72, 71, 74, 168, 25, 57, 156, 157, 89, 252, 212, 3, 94, 126, 190, 230, 200, 100, 108, 247, 38, 83, 144, 65, 230, 96, 242, 75, 4, 79, 88, 87, 221, 77, 74, 15, 79, 184, 221, 236, 9, 74, 105, 123, 251, 94, 67, 240, 53, 133, 62, 165, 38, 211, 12, 164, 42, 201, 213, 105, 252, 66, 10, 15, 216, 85, 98, 50, 5, 60, 46, 126, 50, 199, 136, 129, 134, 52, 37, 81, 102, 123, 112, 60, 165, 72, 224, 171, 193, 47, 184, 64, 226, 218, 189, 181, 111, 108, 101, 145, 248, 31, 0, 230, 124, 156, 171, 162, 25, 95, 32, 52, 137, 144, 161, 22, 3, 113, 51, 164, 221, 36, 62, 126, 251, 21, 174, 135, 21, 164, 207, 76, 162, 226, 232, 124, 38, 54, 136, 182, 30, 192, 178, 115, 122, 194, 181, 3, 230, 9, 110, 89, 32, 238, 59, 43, 43, 175, 76, 27, 93, 111, 12, 206, 131, 201, 70, 194, 179, 199, 138, 102, 57, 13, 91, 95, 91, 61, 56, 146, 175, 172, 18, 162, 50, 0, 23, 139, 163, 240, 178, 194, 115, 133, 93, 172, 154, 84, 167, 239, 234, 135, 146, 113, 145, 12, 250, 223, 22, 113, 83, 21, 81, 107, 93, 43, 125, 148, 193, 112, 29, 90, 51, 21, 36, 28, 13, 185, 209, 23, 189, 229, 89, 169, 32, 33, 56, 33, 90, 204, 212, 145, 139, 58, 73, 225, 145, 187, 6, 142, 29, 40, 95, 224, 141, 223, 47, 209, 29, 11, 23, 87, 96, 168, 162, 133, 35, 147, 190, 153, 232, 101, 76, 226, 62, 188, 82, 81, 70, 98, 242, 29, 247, 218, 162, 217, 173, 7, 72, 106, 106, 178, 240, 26, 154, 92, 84, 253, 130, 93, 202, 153, 24, 102, 142, 162, 212, 141, 63, 19, 124, 223, 133, 220, 70, 10, 17, 148, 3, 100, 224, 82, 124, 103, 253, 115, 103, 174, 177, 126, 148, 52, 240, 199, 232, 152, 207, 198, 161, 245, 128, 215, 234, 107, 36, 43, 221, 201, 37, 15, 15, 47, 101, 151, 205, 216, 182, 78, 68, 33, 240, 134, 11, 107, 97, 60, 55, 80, 128, 70, 16, 56, 228, 116, 3, 194, 135, 12, 206, 170, 121, 124, 35, 101, 229, 124, 209, 148, 109, 248, 224, 90, 50, 191, 181, 204, 121, 107, 59, 91, 196, 95, 17, 192, 188, 128, 154, 44, 154, 200, 241, 50, 232, 145, 122, 244, 188, 10, 115, 115, 28, 87, 12, 3, 110, 218, 2, 44, 119, 208, 138, 3, 214, 202, 8, 249, 125, 39, 76, 79, 111, 105, 61, 25, 30, 153, 206, 65, 80, 36, 159, 171, 21, 202, 66, 147, 119, 52, 140, 250, 137, 104, 131, 167, 190, 6, 129, 166, 133, 110, 214, 238, 0, 184, 252, 209, 228, 124, 100, 201, 87, 28, 200, 38, 239, 210, 104, 102, 66, 185, 236, 62, 151, 166, 177, 18, 223, 212, 167, 251, 240, 206, 128, 24, 163, 141, 81, 164, 57, 20, 66, 17, 132, 160, 35, 142, 223, 118, 165, 200, 142, 178, 225, 26, 225, 139, 238, 243, 217, 20, 245, 167, 16, 46, 67, 44, 216, 140, 229, 175, 151, 43, 201, 178, 64, 102, 231, 32, 191, 166, 64, 150, 72, 112, 218, 91, 114, 197, 206, 141, 251, 172, 201, 99, 160, 59, 111, 174, 27, 231, 123, 134, 32, 101, 84, 59, 90, 59, 239, 98, 204, 93, 158, 53, 200, 130, 202, 157, 118, 242, 72, 18, 245, 48, 96, 24, 93, 96, 121, 34, 97, 199, 84, 33, 58, 253, 165, 62, 95, 146, 219, 45, 209, 237, 111, 160, 126, 191, 68, 135, 213, 62, 149, 51, 88, 239, 92, 160, 37, 54, 227, 32, 59, 240, 118, 249, 233, 214, 248, 173, 69, 135, 91, 55, 8, 222, 167, 170, 171, 188, 155, 83, 5, 76, 224, 162, 90, 188, 254, 192, 71, 90, 100, 154, 142, 136, 52, 179, 160, 4, 33, 229, 165, 173, 87, 176, 150, 61, 166, 251, 22, 217, 74, 16, 250, 248, 169, 163, 228, 73, 233, 253, 101, 128, 230, 203, 244, 207, 1, 172, 53, 60, 193, 201, 128, 144, 104, 142, 101, 102, 194, 20, 120, 136, 160, 43, 245, 174, 86, 136, 19, 97, 235, 223, 236, 143, 107, 171, 39, 70, 178, 112, 129, 121, 15, 171, 218, 231, 84, 56, 89, 232, 231, 113, 173, 88, 190, 137, 56, 118, 143, 32, 58, 154, 207, 245, 209, 48, 187, 56, 140, 222, 41, 150, 254, 5, 10, 227, 195, 222, 40, 140, 167, 120, 119, 172, 67, 159, 253, 193, 63, 81, 59, 86, 172, 36, 255, 17, 132, 179, 135, 0, 88, 255, 242, 18, 142, 9, 247, 47, 178, 165, 181, 154, 109, 98, 52, 121, 232, 115, 16, 37, 28, 234, 167, 167, 238, 4, 225, 90, 106, 241, 44, 147, 227, 15, 127, 45, 72, 47, 99, 209, 6, 160, 92, 107, 121, 185, 231, 152, 157, 168, 186, 137, 16, 231, 56, 243, 138, 169, 237, 37, 191, 181, 156, 202, 193, 124, 115, 42, 16, 66, 223, 47, 158, 22, 25, 140, 152, 184, 18, 15, 143, 98, 242, 43, 114, 93, 134, 25, 233, 174, 242, 170, 61, 66, 101, 115, 154, 224, 75, 162, 21, 201, 194, 3, 98, 135, 80, 24, 240, 27, 7, 52, 195, 161, 69, 189, 92, 124, 181, 187, 128, 28, 35, 106, 156, 143, 9, 226, 76, 8, 28, 188, 0, 54, 227, 74, 207, 77, 80, 93, 161, 122, 82, 225, 32, 150, 163, 223, 118, 99, 111, 120, 19, 18, 80, 200, 17, 25, 91, 158, 195, 3, 76, 89, 46, 163, 51, 104, 229, 155, 203, 58, 52, 24, 2, 181, 152, 105, 80, 246, 153, 1, 94, 236, 201, 67, 47, 164, 153, 50, 68, 192, 191, 47, 96, 253, 36, 63, 175, 190, 80, 10, 151, 72, 29, 168, 190, 172, 3, 217, 6, 156, 218, 158, 176, 92, 126, 173, 229, 116, 98, 249, 213, 46, 253, 122, 14, 211, 159, 114, 99, 68, 168, 55, 230, 94, 149, 40, 9, 31, 9, 205, 91, 147, 14, 24, 197, 63, 216, 168, 168, 239, 38, 61, 172, 238, 149, 58, 9, 19, 138, 183, 39, 168, 66, 63, 61, 0, 33, 86, 194, 158, 221, 89, 15, 166, 71, 16, 35, 231, 240, 88, 91, 197, 233, 229, 124, 214, 138, 177, 76, 176, 99, 209, 218, 80, 211, 113, 55, 238, 189, 137, 79, 73, 176, 86, 1, 50, 174, 22, 16, 92, 223, 56, 102, 80, 130, 72, 30, 71, 178, 59, 4, 76, 175, 75, 92, 105, 31, 122, 34, 213, 82, 121, 202, 151, 17, 240, 255, 76, 49, 156, 82, 191, 69, 162, 121, 240, 104, 182, 148, 201, 196, 195, 162, 172, 107, 57, 12, 168, 197, 227, 202, 4, 131, 158, 203, 29, 156, 152, 59, 118, 224, 52, 195, 36, 10, 94, 1, 140, 209, 178, 65, 23, 137, 8, 255, 205, 88, 114, 18, 106, 14, 184, 30, 128, 210, 199, 98, 194, 44, 141, 80, 194, 255, 249, 21, 140, 197, 72, 112, 212, 238, 11, 142, 197, 13, 115, 16, 164, 242, 140, 60, 189, 105, 156, 248, 176, 73, 243, 226, 79, 192, 212, 224, 216, 123, 52, 126, 179, 189, 156, 224, 232, 75, 52, 66, 186, 21, 2, 118, 236, 10, 134, 129, 55, 114, 130, 15, 40, 47, 235, 31, 81, 39, 216, 99, 81, 231, 170, 39, 69, 53, 173, 7, 169, 180, 69, 86, 133, 178, 227, 160, 243, 100, 144, 57, 9, 177, 109, 236, 243, 254, 208, 133, 98, 249, 177, 78, 162, 55, 194, 130, 21, 51, 119, 104, 233, 81, 135, 62, 102, 245, 44, 88, 110, 73, 157, 226, 11, 140, 163, 19, 132, 100, 3, 31, 222, 202, 95, 29, 20, 109, 53, 86, 247, 31, 113, 9, 224, 130, 180, 104, 4, 223, 17, 205, 207, 166, 7, 246, 244, 196, 164, 25, 75, 15, 121, 107, 255, 211, 56, 195, 111, 248, 255, 182, 10, 107, 226, 123, 180, 165, 63, 168, 203, 9, 174, 156, 31, 102, 150, 242, 62, 235, 249, 47, 27, 152, 58, 208, 203, 224, 163, 227, 171, 205, 12, 187, 224, 139, 151, 133, 222, 121, 36, 61, 254, 248, 196, 172, 103, 195, 98, 193, 211, 190, 126, 45, 44, 155, 20, 65, 168, 51, 144, 51, 152, 46, 233, 112, 36, 15, 73, 239, 5, 120, 236, 179, 40, 207, 2, 153, 155, 92, 65, 43, 84, 48, 124, 219, 146, 91, 13, 201, 252, 211, 243, 227, 40, 221, 221, 248, 235, 156, 194, 5, 130, 155, 74, 102, 186, 167, 114, 40, 254, 61, 236, 250, 157, 132, 124, 78, 250, 212, 250, 209, 77, 112, 243, 80, 60, 52, 34, 237, 38, 115, 243, 239, 49, 113, 211, 186, 24, 120, 139, 133, 14, 247, 115, 84, 254, 253, 72, 163, 20, 151, 225, 143, 126, 8, 38, 69, 130, 4, 84, 143, 48, 32, 218, 130, 136, 109, 251, 253, 93, 184, 152, 23, 4, 182, 201, 193, 151, 206, 238, 151, 206, 13, 43, 255, 7, 153, 194, 240, 1, 30, 149, 44, 235, 44, 14, 185, 111, 237, 183, 199, 54, 121, 208, 84, 220, 196, 244, 138, 24, 186, 36, 245, 254, 19, 61, 73, 239, 248, 73, 49, 175, 169, 211, 59, 88, 180, 56, 230, 78, 92, 235, 61, 34, 187, 177, 236, 187, 158, 226, 120, 159, 108, 54, 95, 188, 219, 130, 41, 72, 162, 199, 22, 176, 38, 231, 86, 132, 237, 227, 18, 148, 185, 93, 9, 157, 188, 181, 199, 57, 83, 250, 185, 10, 34, 102, 175, 233, 91, 27, 166, 27, 68, 128, 35, 97, 159, 40, 133, 88, 118, 225, 128, 69, 31, 1, 96, 88, 219, 151, 4, 89, 235, 54, 180, 246, 192, 240, 42, 4, 229, 40, 26, 37, 175, 82, 132, 106, 96, 95, 176, 174, 103, 238, 70, 91, 231, 179, 4, 237, 240, 118, 137, 154, 50, 120, 124, 171, 157, 197, 150, 121, 154, 119, 85, 167, 48, 30, 98, 57, 14, 239, 46, 36, 131, 93, 152, 183, 94, 221, 46, 20, 32, 63, 189, 192, 12, 37, 29, 96, 48, 95, 83, 233, 131, 139, 12, 222, 136, 246, 159, 235, 123, 191, 190, 77, 19, 135, 185, 55, 210, 202, 170, 84, 200, 253, 126, 241, 227, 80, 184, 199, 218, 95, 6, 119, 112, 204, 13, 65, 226, 86, 248, 44, 94, 14, 120, 40, 221, 214, 140, 20, 238, 241, 87, 43, 33, 27, 48, 230, 178, 210, 158, 234, 128, 232, 177, 228, 187, 127, 130, 236, 147, 194, 174, 139, 182, 5, 214, 102, 49, 144, 134, 49, 166, 247, 127, 104, 18, 29, 125, 198, 242, 190, 113, 11, 123, 114, 60, 146, 156, 15, 198, 93, 129, 177, 12, 183, 68, 110, 239, 97, 116, 184, 24, 146, 10, 71, 96, 54, 107, 110, 87, 141, 124, 45, 62, 151, 107, 229, 220, 167, 18, 127, 183, 197, 219, 87, 142, 188, 210, 163, 107, 109, 129, 68, 26, 249, 240, 66, 76, 101, 46, 204, 115, 179, 239, 12, 63, 196, 172, 134, 79, 177, 133, 111, 75, 236, 101, 85, 196, 210, 218, 229, 15, 151, 197, 119, 73, 223, 216, 88, 216, 86, 249, 121, 203, 178, 8, 179, 71, 18, 191, 24, 48, 148, 59, 151, 72, 233, 7, 237, 250, 117, 144, 135, 59, 184, 119, 4, 88, 150, 53, 27, 81, 241, 90, 68, 1, 58, 187, 55, 100, 27, 220, 60, 79, 104, 117, 31, 118, 250, 113, 253, 187, 66, 215, 212, 164, 212, 39, 69, 91, 38, 90, 119, 11, 23, 76, 112, 138, 114, 114, 105, 109, 156, 85, 181, 142, 142, 37, 49, 233, 7, 51, 77, 23, 211, 208, 155, 61, 243, 53, 94, 187, 225, 108, 148, 179, 64, 75, 149, 156, 22, 180, 94, 232, 224, 222, 63, 76, 54, 51, 30, 251, 179, 226, 32, 33, 250, 88, 59, 127, 170, 249, 71, 127, 206, 253, 88, 122, 33, 229, 230, 76, 227, 74, 190, 231, 186, 189, 81, 31, 242, 73, 166, 234, 61, 217, 90, 186, 5, 83, 122, 212, 89, 126, 63, 241, 101, 185, 166, 1, 90, 170, 121, 152, 248, 128, 154, 198, 58, 176, 187, 91, 237, 121, 50, 190, 168, 176, 201, 31, 204, 193, 219, 83, 180, 61, 95, 112, 92, 123, 51, 158, 234, 121, 34, 0, 165, 62, 98, 194, 238, 151, 185, 190, 179, 157, 219, 58, 218, 189, 91, 240, 117, 121, 174, 97, 204, 102, 2, 135, 249, 200, 217, 170, 246, 95, 9, 124, 224, 77, 119, 60, 113, 78, 231, 174, 109, 45, 78, 55, 249, 134, 174, 144, 12, 158, 78, 5, 175, 124, 62, 150, 86, 255, 253, 254, 105, 252, 197, 86, 94, 149, 16, 126, 187, 156, 142, 66, 172, 83, 158, 18, 93, 200, 137, 30, 205, 253, 46, 130, 27, 224, 179, 22, 253, 50, 162, 178, 63, 24, 18, 183, 21, 33, 218, 178, 41, 154, 238, 138, 149, 203, 94, 65, 218, 184, 85, 232, 213, 67, 34, 146, 17, 71, 137, 18, 125, 38, 86, 199, 86, 9, 225, 174, 182, 236, 133, 91, 72, 148, 246, 200, 148, 68, 20, 96, 189, 75, 78, 243, 144, 5, 80, 173, 75, 42, 63, 126, 194, 85, 57, 84, 91, 230, 50, 145, 253, 225, 139, 158, 70, 230, 129, 246, 105, 214, 181, 139, 79, 210, 52, 218, 45, 99, 35, 30, 64, 55, 161, 201, 240, 216, 182, 65, 229, 46, 244, 236, 109, 223, 145, 147, 157, 22, 207, 197, 67, 45, 164, 228, 20, 148, 186, 222, 49, 113, 127, 58, 241, 228, 216, 168, 223, 238, 134, 232, 76, 211, 138, 251, 204, 153, 252, 38, 53, 199, 209, 22, 231, 146, 159, 77, 187, 98, 143, 62, 163, 46, 63, 48, 42, 77, 174, 247, 98, 197, 83, 5, 77, 239, 196, 86, 248, 172, 240, 62, 141, 177, 207, 132, 251, 81, 100, 253, 17, 9, 44, 19, 134, 144, 173, 208, 63, 232, 0, 210, 146, 180, 42, 250, 204, 68, 195, 27, 92, 122, 254, 182, 120, 21, 135, 177, 178, 206, 69, 231, 107, 105, 254, 213, 185, 31, 29, 250, 161, 199, 243, 220, 213, 226, 66, 0, 187, 219, 158, 111, 160, 129, 110, 113, 188, 134, 64, 178, 124, 32, 238, 30, 123, 51, 41, 116, 14, 103, 69, 187, 78, 105, 253, 10, 46, 6, 2, 122, 95, 201, 97, 36, 209, 150, 177, 210, 156, 38, 246, 174, 25, 189, 44, 101, 213, 192, 148, 239, 25, 15, 212, 8, 121, 37, 87, 124, 1, 252, 192, 225, 17, 33, 110, 52, 44, 171, 101, 212, 20, 235, 169, 168, 62, 163, 14, 204, 230, 47, 69, 175, 151, 229, 171, 222, 67, 245, 19, 97, 38, 79, 7, 246, 99, 230, 251, 181, 3, 210, 61, 178, 47, 138, 28, 113, 59, 122, 144, 249, 25, 191, 0, 67, 157, 59, 23, 71, 73, 234, 143, 168, 118, 53, 181, 146, 107, 43, 53, 171, 173, 15, 22, 84, 217, 189, 12, 54, 239, 15, 200, 30, 253, 206, 7, 193, 28, 220, 28, 103, 123, 160, 149, 98, 127, 231, 70, 1, 94, 191, 171, 167, 88, 73, 58, 47, 13, 52, 181, 86, 55, 233, 239, 174, 228, 249, 79, 65, 93, 128, 174, 13, 86, 144, 216, 235, 246, 98, 132, 142, 187, 144, 252, 68, 3, 170, 238, 203, 198, 75, 240, 25, 53, 234, 231, 91, 187, 189, 224, 71, 120, 176, 48, 64, 9, 163, 25, 33, 48, 198, 153, 14, 254, 183, 90, 101, 15, 137, 127, 71, 5, 230, 56, 246, 195, 46, 243, 50, 184, 123, 219, 77, 95, 84, 251, 227, 145, 57, 133, 159, 100, 40, 0, 213, 92, 127, 223, 152, 134, 252, 19, 8, 101, 78, 174, 110, 17, 153, 240, 88, 110, 45, 91, 46, 88, 115, 236, 189, 2, 67, 23, 45, 6, 228, 126, 80, 102, 128, 99, 20, 118, 255, 98, 13, 26, 17, 254, 175, 42, 0, 7, 126, 44, 142, 154, 204, 6, 22, 60, 65, 193, 161, 193, 76, 26, 141, 61, 130, 15, 203, 96, 216, 79, 192, 188, 51, 182, 144, 151, 178, 185, 228, 249, 176, 180, 13, 61, 223, 196, 102, 32, 108, 231, 206, 113, 193, 2, 204, 80, 51, 240, 227, 253, 6, 185, 176, 203, 65, 109, 222, 58, 132, 241, 43, 232, 73, 190, 66, 102, 54, 40, 89, 219, 157, 136, 186, 88, 125, 113, 144, 52, 206, 139, 250, 13, 104, 244, 10, 176, 145, 47, 12, 103, 4, 140, 119, 106, 20, 208, 239, 131, 61, 72, 151, 178, 208, 209, 94, 126, 47, 29, 151, 170, 10, 135, 178, 212, 249, 39, 152, 102, 221, 138, 2, 84, 51, 236, 224, 24, 179, 172, 92, 222, 121, 85, 54, 178, 17, 25, 38, 203, 126, 60, 152, 252, 238, 207, 20, 205, 11, 92, 11, 103, 229, 36, 126, 89, 138, 206, 240, 78, 87, 5, 72, 90, 199, 166, 174, 89, 174, 140, 0, 16, 239, 123, 10, 38, 26, 69, 120, 155, 86, 160, 173, 214, 59, 199, 25, 31, 40, 48, 153, 185, 9, 211, 102, 9, 38, 116, 45, 140, 128, 69, 134, 255, 174, 193, 112, 167, 16, 93, 131, 140, 185, 151, 147, 144, 93, 248, 249, 139, 157, 121, 126, 217, 211, 82, 46, 60, 131, 80, 184, 222, 189, 238, 196, 141, 190, 17, 135, 228, 181, 211, 58, 64, 93, 39, 137, 170, 106, 94, 201, 186, 118, 99, 180, 219, 141, 75, 109, 140, 150, 147, 251, 64, 0, 18, 76, 73, 143, 207, 120, 190, 178, 10, 238, 187, 44, 120, 78, 151, 123, 152, 24, 179, 136, 50, 101, 170, 177, 81, 172, 145, 232, 42, 230, 217, 131, 195, 60, 98, 157, 144, 29, 10, 16, 59, 168, 99, 45, 142, 170, 132, 38, 113, 13, 129, 96, 28, 7, 214, 126, 249, 238, 128, 49, 121, 168, 118, 109, 119, 185, 40, 154, 32, 18, 0, 141, 18, 123, 160, 26, 187, 206, 58, 126, 240, 229, 34, 29, 246, 192, 80, 250, 17, 40, 79, 63, 125, 141, 205, 56, 59, 33, 122, 165, 147, 50, 104, 94, 138, 166, 129, 34, 135, 210, 44, 183, 169, 235, 151, 35, 146, 198, 132, 107, 72, 80, 127, 24, 35, 190, 197, 89, 212, 134, 131, 68, 210, 40, 35, 231, 54, 8, 233, 2, 254, 64, 1, 120, 224, 116, 144, 97, 238, 78, 150, 99, 248, 157, 48, 137, 77, 40, 58, 56, 132, 108, 222, 77, 147, 11, 88, 61, 201, 251, 75, 195, 177, 249, 159, 163, 65, 207, 137, 107, 58, 251, 108, 59, 101, 42, 219, 186, 30, 186, 20, 248, 49, 218, 203, 211, 42, 241, 215, 175, 117, 159, 252, 240, 221, 105, 20, 45, 226, 183, 21, 77, 91, 226, 60, 90, 29, 127, 50, 29, 207, 112, 177, 216, 142, 254, 37, 216, 195, 139, 226, 62, 175, 153, 63, 191, 191, 109, 58, 135, 99, 95, 224, 146, 91, 18, 52, 139, 208, 68, 159, 74, 117, 51, 167, 22, 0, 250, 168, 105, 110, 203, 219, 133, 255, 65, 222, 240, 52, 190, 16, 105, 218, 62, 249, 152, 175, 5, 230, 92, 5, 1, 211, 137, 52, 95, 208, 192, 198, 204, 46, 163, 191, 177, 60, 171, 88, 108, 199, 49, 208, 107, 165, 123, 254, 107, 34, 236, 155, 207, 221, 76, 194, 126, 6, 95, 43, 211, 83, 14, 34, 165, 187, 213, 181, 138, 40, 26, 66, 232, 136, 125, 107, 191, 165, 177, 17, 26, 114, 202, 208, 97, 29, 218, 241, 54, 216, 26, 15, 186, 95, 101, 138, 180, 121, 210, 153, 56, 167, 102, 41, 30, 201, 97, 97, 118, 192, 121, 108, 48, 153, 124, 90, 245, 87, 129, 105, 195, 211, 44, 210, 16, 194, 179, 52, 233, 248, 225, 131, 84, 96, 35, 58, 40, 193, 29, 246, 213, 133, 223, 68, 196, 244, 78, 11, 224, 123, 156, 21, 149, 50, 162, 235, 63, 238, 41, 189, 156, 118, 22, 58, 21, 49, 62, 72, 1, 228, 92, 69, 109, 162, 82, 32, 13, 178, 116, 222, 192, 32, 146, 227, 201, 184, 123, 45, 217, 188, 118, 142, 23, 65, 5, 167, 6, 221, 116, 145, 196, 204, 56, 178, 100, 86, 181, 59, 38, 37, 40, 244, 131, 205, 15, 173, 169, 74, 223, 251, 85, 109, 232, 244, 123, 98, 241, 205, 174, 190, 173, 131, 182, 253, 229, 45, 35, 216, 209, 206, 251, 197, 234, 207, 193, 11, 108, 241, 100, 107, 178, 68, 153, 243, 92, 153, 109, 71, 245, 40, 207, 237, 183, 157, 229, 17, 37, 198, 164, 205, 212, 16, 240, 88, 27, 127, 64, 117, 113, 213, 52, 66, 178, 250, 126, 110, 66, 42, 29, 71, 116, 183, 232, 31, 176, 110, 200, 76, 19, 1, 52, 109, 243, 80, 213, 227, 68, 67, 85, 180, 67, 19, 78, 6, 13, 97, 176, 115, 42, 6, 30, 111, 68, 224, 29, 49, 21, 102, 65, 253, 232, 152, 255, 21, 114, 144, 6, 151, 12, 255, 130, 226, 168, 12, 204, 244, 17, 49, 199, 247, 206, 214, 107, 221, 80, 62, 154, 103, 139, 136, 21, 37, 91, 60, 127, 251, 171, 9, 28, 184, 141, 91, 53, 151, 127, 161, 83, 118, 127, 234, 185, 94, 193, 193, 103, 61, 117, 170, 158, 190, 239, 99, 110, 166, 94, 128, 111, 135, 203, 203, 174, 127, 226, 231, 242, 198, 202, 86, 229, 197, 254, 208, 10, 193, 104, 160, 3, 129, 104, 229, 58, 232, 129, 80, 52, 42, 164, 217, 101, 219, 76, 25, 111, 170, 226, 229, 22, 212, 247, 61, 0, 36, 134, 176, 74, 159, 204, 17, 203, 56, 66, 41, 103, 183, 74, 37, 67, 142, 229, 50, 89, 188, 239, 6, 210, 55, 238, 70, 222, 223, 230, 59, 185, 22, 34, 14, 101, 72, 117, 221, 215, 127, 82, 234, 229, 28, 59, 32, 146, 143, 184, 247, 72, 47, 143, 73, 57, 145, 190, 183, 179, 39, 135, 9, 225, 220, 72, 53, 16, 225, 176, 211, 17, 242, 156, 20, 227, 80, 226, 130, 96, 201, 122, 252, 12, 164, 102, 61, 130, 166, 217, 156, 8, 78, 60, 234, 174, 25, 58, 146, 101, 191, 226, 151, 230, 127, 217, 66, 225, 121, 149, 55, 77, 118, 21, 202, 123, 117, 128, 180, 145, 225, 159, 102, 190, 251, 67, 124, 73, 25, 131, 222, 130, 243, 34, 192, 8, 37, 81, 250, 177, 89, 93, 177, 202, 19, 105, 110, 229, 57, 45, 135, 133, 162, 201, 185, 83, 74, 23, 115, 250, 154, 7, 172, 19, 218, 131, 67, 133, 185, 140, 29, 58, 107, 100, 230, 249, 71, 44, 95, 21, 180, 87, 22, 156, 252, 171, 55, 220, 201, 204, 115, 210, 13, 132, 111, 163, 93, 95, 17, 1, 69, 14, 14, 40, 61, 213, 163, 46, 185, 241, 30, 7, 199, 48, 182, 107, 148, 150, 231, 226, 230, 32, 147, 181, 70, 187, 21, 253, 124, 192, 60, 105, 168, 61, 121, 201, 30, 129, 85, 70, 135, 151, 173, 161, 11, 74, 228, 89, 21, 79, 254, 122, 173, 211, 116, 118, 7, 26, 48, 79, 181, 231, 163, 76, 194, 108, 19, 104, 174, 53, 112, 219, 113, 126, 160, 128, 2, 168, 219, 81, 163, 215, 36, 168, 12, 142, 152, 237, 183, 18, 236, 203, 132, 11, 41, 16, 249, 210, 25, 4, 246, 207, 87, 207, 98, 218, 36, 157, 86, 220, 65, 45, 25, 89, 7, 86, 236, 4, 65, 36, 25, 168, 94, 252, 106, 233, 175, 180, 33, 163, 33, 88, 219, 175, 193, 102, 61, 62, 85, 99, 250, 197, 209, 130, 201, 81, 218, 80, 187, 247, 174, 101, 81, 212, 161, 14, 100, 188, 75, 199, 196, 187, 31, 220, 207, 177, 93, 72, 230, 221, 59, 198, 27, 49, 38, 165, 52, 3, 227, 59, 204, 147, 186, 183, 117, 148, 240, 223, 79, 136, 61, 139, 145, 228, 48, 231, 57, 224, 219, 140, 1, 245, 237, 87, 62, 61, 92, 120, 67, 25, 152, 150, 147, 149, 253, 242, 36, 117, 248, 171, 184, 233, 133, 147, 112, 200, 100, 63, 101, 156, 132, 214, 156, 75, 106, 56, 160, 139, 221, 49, 195, 136, 40, 85, 126, 46, 59, 245, 200, 11, 148, 90, 39, 7, 199, 71, 23, 57, 107, 34, 2, 215, 94, 217, 115, 221, 167, 44, 227, 175, 222, 167, 13, 255, 5, 20, 238, 203, 69, 127, 200, 120, 178, 230, 34, 41, 40, 247, 38, 129, 246, 244, 159, 13, 207, 148, 130, 155, 104, 62, 31, 181, 2, 249, 117, 78, 79, 31, 33, 246, 221, 17, 179, 20, 139, 200, 119, 243, 156, 27, 215, 251, 174, 190, 227, 61, 224, 82, 162, 11, 250, 11, 88, 221, 172, 245, 170, 143, 210, 186, 213, 173, 141, 195, 214, 73, 243, 130, 249, 2, 137, 155, 155, 102, 231, 225, 212, 82, 79, 129, 89, 131, 79, 67, 78, 151, 165, 195, 61, 218, 244, 60, 196, 233, 121, 9, 124, 13, 10, 64, 246, 245, 150, 140, 90, 188, 20, 179, 41, 74, 210, 206, 65, 255, 61, 223, 169, 63, 20, 23, 23, 168, 43, 67, 242, 83, 162, 54, 123, 83, 12, 233, 247, 249, 69, 184, 232, 201, 245, 164, 213, 75, 222, 7, 27, 145, 224, 227, 212, 204, 183, 121, 240, 193, 251, 239, 82, 189, 81, 177, 130, 157, 12, 52, 81, 187, 45, 186, 31, 86, 61, 164, 160, 204, 143, 154, 16, 59, 21, 161, 69, 214, 86, 30, 64, 174, 80, 58, 166, 210, 5, 148, 248, 220, 116, 33, 20, 212, 82, 202, 132, 244, 10, 117, 15, 167, 32, 130, 148, 178, 88, 238, 90, 86, 183, 252, 67, 100, 251, 134, 45, 232, 95, 218, 114, 202, 172, 75, 108, 124, 73, 19, 196, 54, 107, 205, 185, 34, 249, 37, 55, 3, 2, 114, 188, 35, 94, 82, 0, 97, 167, 131, 241, 186, 207, 160, 242, 168, 40, 230, 124, 55, 97, 147, 115, 202, 197, 54, 35, 142, 209, 177, 105, 221, 88, 189, 136, 86, 51, 77, 203, 156, 190, 159, 172, 222, 67, 57, 108, 197, 88, 202, 90, 250, 95, 106, 183, 86, 45, 208, 219, 90, 253, 246, 72, 110, 144, 50, 147, 143, 35, 64, 132, 227, 167, 248, 174, 247, 241, 66, 244, 172, 127, 98, 31, 67, 3, 208, 220, 168, 132, 1, 195, 238, 207, 63, 171, 195, 189, 43, 68, 124, 121, 218, 255, 213, 68, 11, 59, 78, 89, 68, 146, 17, 87, 148, 172, 31, 140, 167, 199, 163, 37, 250, 242, 122, 31, 187, 221, 13, 159, 226, 162, 197, 54, 144, 1, 16, 203, 71, 181, 223, 158, 253, 101, 204, 13, 94, 32, 250, 220, 49, 192, 229, 48, 9, 175, 34, 204, 100, 200, 157, 206, 137, 131, 139, 8, 71, 15, 186, 169, 210, 204, 154, 115, 224, 23, 86, 180, 249, 54, 52, 123, 49, 57, 56, 189, 189, 172, 107, 134, 220, 207, 215, 150, 120, 238, 144, 184, 30, 71, 53, 35, 126, 88, 100, 137, 101, 175, 159, 94, 158, 41, 88, 179, 234, 58, 19, 57, 10, 185, 133, 161, 153, 194, 71, 100, 221, 150, 174, 226, 2, 105, 191, 213, 205, 159, 217, 13, 72, 132, 67, 140, 216, 188, 68, 239, 242, 145, 42, 162, 182, 224, 148, 18, 12, 47, 201, 84, 139, 242, 44, 15, 148, 223, 66, 177, 214, 102, 184, 168, 175, 76, 12, 71, 155, 101, 14, 214, 134, 29, 75, 128, 34, 229, 36, 172, 215, 154, 234, 215, 120, 162, 137, 112, 235, 106, 66, 179, 176, 20, 25, 108, 13, 178, 29, 168, 205, 41, 210, 85, 228, 79, 237, 228, 42, 213, 226, 135, 186, 2, 97, 100, 209, 217, 196, 158, 129, 222, 133, 144, 184, 43, 236, 160, 244, 156, 98, 77, 156, 233, 160, 152, 250, 126, 232, 75, 54, 162, 51, 198, 64, 9, 101, 240, 102, 47, 51, 161, 19, 224, 97, 118, 193, 236, 204, 15, 157, 176, 35, 203, 14, 166, 56, 207, 190, 80, 15, 100, 80, 0, 229, 5, 89, 84, 94, 239, 117, 157, 211, 206, 150, 226, 137, 227, 167, 196, 113, 98, 219, 13, 114, 1, 31, 123, 99, 199, 255, 98, 74, 8, 43, 111, 120, 170, 16, 248, 146, 162, 224, 243, 10, 186, 243, 122, 115, 219, 250, 19, 19, 88, 228, 69, 221, 134, 108, 141, 53, 253, 231, 80, 162, 206, 166, 10, 47, 4, 222, 73, 229, 211, 70, 165, 179, 133, 216, 228, 228, 224, 189, 129, 132, 126, 5, 121, 151, 181, 177, 100, 109, 85, 46, 38, 43, 196, 121, 10, 144, 202, 178, 236, 156, 243, 91, 162, 132, 221, 4, 84, 186, 140, 123, 238, 56, 20, 241, 233, 108, 82, 51, 68, 229, 221, 97, 149, 41, 5, 214, 46, 57, 191, 146, 212, 209, 108, 60, 212, 159, 139, 58, 56, 189, 80, 164, 41, 150, 145, 163, 74, 162, 196, 114, 57, 202, 141, 175, 86, 92, 62, 89, 37, 185, 77, 246, 206, 32, 210, 239, 107, 87, 215, 182, 95, 12, 40, 155, 67, 191, 195, 108, 202, 38, 150, 141, 211, 131, 131, 225, 135, 225, 71, 215, 119, 20, 223, 147, 200, 124, 218, 48, 23, 235, 136, 70, 30, 239, 71, 28, 59, 183, 163, 219, 79, 165, 118, 93, 195, 250, 90, 127, 117, 9, 82, 162, 34, 115, 9, 5, 200, 188, 75, 214, 87, 10, 169, 34, 73, 41, 203, 21, 67, 88, 224, 147, 143, 211, 146, 33, 110, 156, 159, 137, 118, 182, 59, 42, 91, 208, 247, 254, 162, 7, 32, 137, 249, 17, 3, 24, 64, 219, 178, 22, 254, 237, 173, 5, 148, 226, 61, 121, 1, 61, 126, 34, 110, 196, 0, 81, 61, 91, 210, 208, 5, 75, 170, 79, 215, 148, 54, 219, 165, 252, 241, 2, 105, 238, 107, 102, 175, 108, 63, 48, 214, 188, 48, 206, 177, 196, 211, 254, 252, 127, 99, 244, 23, 232, 154, 151, 182, 98, 170, 2, 129, 167, 87, 74, 70, 19, 39, 204, 110, 127, 144, 90, 73, 63, 225, 66, 9, 29, 168, 0, 243, 72, 202, 176, 204, 83, 52, 67, 126, 239, 128, 69, 97, 4, 144, 21, 190, 105, 174, 132, 80, 6, 198, 73, 88, 199, 119, 229, 171, 206, 125, 190, 130, 145, 209, 18, 254, 133, 140, 200, 5, 236, 98, 83, 36, 50, 245, 248, 60, 235, 128, 148, 107, 249, 255, 193, 103, 111, 166, 210, 219, 231, 197, 69, 43, 245, 161, 164, 220, 239, 220, 99, 254, 67, 0, 215, 217, 34, 130, 199, 51, 200, 208, 165, 233, 194, 188, 188, 229, 248, 217, 1, 162, 132, 249, 252, 118, 165, 178, 25, 69, 24, 242, 96, 122, 79, 151, 153, 45, 9, 125, 166, 241, 189, 123, 255, 98, 133, 1, 247, 180, 205, 97, 100, 98, 229, 97, 11, 40, 166, 170, 123, 191, 134, 74, 229, 11, 168, 170, 161, 101, 171, 43, 144, 149, 64, 113, 231, 39, 59, 23, 252, 229, 189, 42, 166, 125, 71, 150, 65, 59, 140, 180, 131, 68, 182, 103, 226, 91, 205, 41, 236, 196, 221, 110, 106, 133, 104, 182, 218, 187, 7, 42, 214, 24, 97, 58, 115, 176, 147, 242, 34, 29, 51, 74, 123, 159, 193, 73, 253, 182, 19, 251, 161, 121, 79, 241, 61, 163, 119, 102, 243, 131, 45, 13, 58, 218, 202, 136, 133, 242, 226, 237, 204, 217, 12, 122, 201, 29, 204, 11, 67, 239, 154, 46, 254, 19, 183, 245, 157, 74, 188, 193, 51, 31, 88, 102, 214, 88, 215, 22, 123, 84, 250, 251, 169, 232, 166, 202, 152, 183, 244, 173, 55, 57, 56, 6, 92, 120, 110, 202, 129, 58, 13, 25, 235, 252, 243, 69, 229, 45, 40, 9, 196, 133, 247, 33, 178, 137, 46, 180, 186, 231, 108, 98, 199, 197, 171, 192, 204, 206, 17, 94, 61, 67, 218, 100, 204, 245, 166, 32, 113, 78, 104, 119, 178, 39, 146, 45, 252, 119, 142, 33, 229, 149, 175, 196, 189, 235, 29, 48, 16, 168, 33, 211, 219, 152, 228, 42, 105, 207, 90, 92, 39, 222, 84, 6, 126, 32, 114, 138, 131, 196, 188, 253, 110, 193, 129, 105, 17, 28, 28, 236, 199, 232, 233, 30, 142, 30, 3, 122, 102, 111, 177, 78, 168, 194, 156, 176, 115, 191, 197, 39, 152, 100, 112, 59, 116, 214, 144, 2, 151, 208, 217, 61, 53, 91, 70, 91, 127, 126, 173, 182, 136, 244, 129, 255, 215, 187, 146, 21, 169, 199, 63, 54, 191, 201, 233, 115, 127, 101, 98, 216, 0, 62, 93, 21, 97, 141, 168, 7, 134, 135, 169, 29, 171, 29, 3, 187, 123, 90, 73, 109, 92, 173, 100, 25, 240, 208, 57, 34, 124, 21, 130, 124, 62, 6, 28, 214, 149, 136, 213, 171, 161, 129, 209, 170, 76, 50, 229, 15, 179, 74, 149, 163, 114, 148, 10, 227, 101, 75, 105, 46, 163, 82, 148, 116, 140, 61, 210, 192, 139, 41, 248, 123, 169, 40, 140, 130, 148, 239, 203, 115, 220, 113, 158, 69, 185, 28, 69, 240, 132, 231, 122, 235, 192, 124, 31, 243, 237, 143, 55, 147, 81, 48, 163, 99, 4, 163, 64, 226, 216, 17, 118, 31, 32, 251, 93, 77, 252, 73, 222, 232, 15, 19, 200, 162, 13, 127, 4, 166, 213, 190, 150, 241, 162, 56, 42, 135, 193, 26, 171, 91, 209, 41, 196, 243, 129, 165, 1, 95, 84, 30, 62, 211, 147, 239, 247, 182, 66, 106, 219, 57, 95, 170, 233, 161, 23, 77, 50, 122, 163, 244, 19, 250, 179, 81, 38, 100, 238, 106, 34, 52, 244, 45, 119, 101, 179, 161, 142, 239, 49, 63, 37, 7, 166, 3, 55, 45, 248, 238, 91, 155, 254, 100, 37, 45, 18, 229, 1, 163, 230, 130, 219, 110, 129, 121, 107, 171, 125, 243, 20, 95, 146, 3, 18, 174, 20, 250, 149, 144, 56, 120, 6, 166, 247, 217, 138, 104, 0, 24, 174, 211, 227, 120, 177, 3, 49, 189, 32, 108, 213, 163, 126, 26, 192, 13, 195, 192, 197, 198, 191, 12, 91, 172, 255, 54, 97, 61, 255, 119, 96, 140, 24, 110, 187, 166, 112, 230, 245, 1, 64, 242, 118, 118, 84, 193, 173, 150, 221, 44, 55, 208, 64, 14, 0, 228, 132, 190, 57, 50, 19, 224, 202, 172, 31, 17, 186, 196, 72, 55, 179, 75, 90, 12, 53, 139, 60, 210, 31, 7, 79, 206, 148, 221, 193, 168, 39, 149, 19, 102, 150, 234, 8, 69, 185, 98, 14, 163, 52, 175, 85, 233, 248, 240, 156, 190, 131, 183, 53, 215, 197, 149, 251, 12, 124, 78, 226, 130, 39, 238, 200, 187, 250, 14, 98, 50, 182, 144, 161, 29, 19, 147, 162, 185, 90, 171, 164, 35, 42, 207, 99, 130, 157, 85, 21, 243, 109, 166, 243, 217, 12, 34, 118, 113, 99, 95, 194, 207, 144, 149, 252, 214, 243, 235, 110, 29, 122, 2, 158, 255, 4, 159, 10, 152, 215, 9, 56, 144, 73, 144, 152, 115, 40, 77, 233, 237, 79, 21, 83, 97, 213, 102, 212, 183, 179, 204, 226, 77, 139, 151, 49, 220, 85, 123, 12, 76, 84, 136, 86, 42, 216, 130, 62, 171, 107, 206, 60, 254, 141, 158, 42, 115, 99, 231, 82, 82, 207, 108, 249, 130, 33, 160, 23, 236, 234, 1, 94, 207, 150, 139, 96, 173, 181, 199, 186, 31, 101, 110, 193, 165, 237, 223, 1, 132, 227, 139, 63, 4, 50, 189, 232, 195, 182, 29, 163, 173, 10, 236, 113, 114, 240, 222, 79, 201, 214, 26, 37, 27, 62, 230, 43, 164, 144, 55, 178, 14, 136, 25, 235, 61, 71, 10, 209, 88, 203, 158, 20, 244, 4, 240, 23, 69, 249, 129, 170, 136, 15, 213, 232, 219, 94, 213, 25, 73, 105, 107, 252};

/* SECP256K1 FUNCTIONS */

SECP256K1 secp256k1_init(void);
void secp256k1_populate_G_doublings_mod_p(APT *);
void secp256k1_free(SECP256K1);
void secp256k1_get_lhs(const SECP256K1, bnz_t *, const bnz_t *); // given y, calculate y^2 mod secp256k1.p
void secp256k1_get_rhs(const SECP256K1, bnz_t *, const bnz_t *); // given x, calculate x^3 + 7 mod secp256k1.p
void secp256k1_point_addition(const SECP256K1, const APT *, const APT *, APT *); // r = (p + q) mod secp256k1.p
void secp256k1_point_doubling(const SECP256K1, const APT *, APT *); // r = 2p mod secp256k1.p
void secp256k1_scalar_multiplication(const SECP256K1, const APT *, const bnz_t *, APT *); // r = q * m mod secp256k1.p
void get_affine_from_jacobian(const SECP256K1, const JPT *, APT *);
void secp256k1_jacobian_point_addition(const SECP256K1, const JPT *, const APT *, JPT *);
void secp256k1_jacobian_scalar_multiplication(const SECP256K1, const bnz_t *, APT *);
bool secp256k1_valid_point(const SECP256K1, const APT);
bool secp256k1_valid_multiplier(const SECP256K1, const bnz_t *);
bool secp256k1_valid_x(const SECP256K1, const bnz_t *);
void secp256k1_get_points_from_valid_x(const SECP256K1, APT *, APT *, const bnz_t *);

SECP256K1 secp256k1_init() // initiate secp256k1 curve, y^2 = (x^3 + 7) mod secp256k1.p
{
    const char *secp256k1_p_str = "115792089237316195423570985008687907853269984665640564039457584007908834671663"; // prime, base 10
    const char *secp256k1_G_x_str = "55066263022277343669578718895168534326250603453777594175500187360389116729240"; // generator x, base 10
    const char *secp256k1_G_y_str = "32670510020758816978083085130507043184471273380659243275938904335757337482424"; // generator y, base 10
    const char *secp256k1_n_str = "115792089237316195423570985008687907852837564279074904382605163141518161494337"; // order, base 10

    SECP256K1 secp256k1;

    bnz_init(&secp256k1.p);
    bnz_init(&secp256k1.a);
    bnz_init(&secp256k1.b);
    bnz_init(&secp256k1.G.x);
    bnz_init(&secp256k1.G.y);
    bnz_init(&secp256k1.n);
    bnz_init(&secp256k1.h);

    bnz_set_str(&secp256k1.p, secp256k1_p_str, 10); // prime
    bnz_set_i32(&secp256k1.a, 0);
    bnz_set_i32(&secp256k1.b, 7);
    bnz_set_str(&secp256k1.G.x, secp256k1_G_x_str, 10); // generator x
    bnz_set_str(&secp256k1.G.y, secp256k1_G_y_str, 10); // generator y
    bnz_set_str(&secp256k1.n, secp256k1_n_str, 10); // order
    bnz_set_i32(&secp256k1.h, 1); // included for completeness, but not used in any functions

    secp256k1_populate_G_doublings_mod_p(secp256k1.G_doublings_mod_p);

    return secp256k1;
}

void secp256k1_populate_G_doublings_mod_p(APT *G_doublings_mod_p)
{
    int i;

    for (i = 0; i < 256; i++) { // initiate and resize bnz_t variables within the G_doublings_mod_p array and populate with data from the g_doublings_data array
        bnz_init(&G_doublings_mod_p[i].x); // initiate x
        bnz_init(&G_doublings_mod_p[i].y); // initiate y
        bnz_resize(&G_doublings_mod_p[i].x, 32, false); // resize x.digits to 32 bytes
        bnz_resize(&G_doublings_mod_p[i].y, 32, false); // resize y.digits to 32 bytes
        memcpy(G_doublings_mod_p[i].x.digits, g_doublings_data + i * 64, 32); // populate x.digits from the g_doublings_data array
        memcpy(G_doublings_mod_p[i].y.digits, g_doublings_data + i * 64 + 32, 32); // populate y.digits from the g_doublings_data array
    }
}

void secp256k1_free(SECP256K1 secp256k1) // free secp256k1 curve
{
    int i;

    bnz_free(&secp256k1.p);
    bnz_free(&secp256k1.a);
    bnz_free(&secp256k1.b);
    bnz_free(&secp256k1.G.x);
    bnz_free(&secp256k1.G.y);

    for (i = 0; i < 256; i++) {
        bnz_free(&secp256k1.G_doublings_mod_p[i].x);
        bnz_free(&secp256k1.G_doublings_mod_p[i].y);
    }

    bnz_free(&secp256k1.n);
    bnz_free(&secp256k1.h);
}

void secp256k1_get_lhs(const SECP256K1 secp256k1, bnz_t *lhs, const bnz_t *y) // given y, calculate y^2 mod secp256k1.p
{
    bnz_multiply_bnz(lhs, y, y); // rhs = y^2
    bnz_mod_bnz(lhs, lhs, &secp256k1.p); // lhs = y^2 mod secp256k1.p
}

void secp256k1_get_rhs(const SECP256K1 secp256k1, bnz_t *rhs, const bnz_t *x) // given x, calculate x^3 + 7 mod secp256k1.p
{
    bnz_multiply_bnz(rhs, x, x); // rhs = x^2
    bnz_multiply_bnz(rhs, rhs, x); // rhs = x^3
    bnz_add_i32(rhs, rhs, 7); // rhs = x^3 + 7
    bnz_mod_bnz(rhs, rhs, &secp256k1.p); // rhs = x^3 + 7 mod secp256k1.p
}

void secp256k1_point_doubling(const SECP256K1 secp256k1, const APT *p, APT *r) // r = 2p mod secp256k1.p
{
    bnz_t slope, tmp;

    APT pp, rr;

    bnz_init(&tmp);
    bnz_init(&slope);

    bnz_init(&pp.x);
    bnz_init(&pp.y);
    bnz_init(&rr.x);
    bnz_init(&rr.y);

    bnz_set_bnz(&pp.x, &p->x);
    bnz_set_bnz(&pp.y, &p->y);
    bnz_set_bnz(&rr.x, &p->x);
    bnz_set_bnz(&rr.y, &p->y);

    if (bnz_is_zero(&pp.y) == false) {
        bnz_multiply_i32(&tmp, &pp.y, 2);
        bnz_modular_multiplicative_inverse(&tmp, &tmp, &secp256k1.p);
        bnz_multiply_bnz(&slope, &pp.x, &pp.x);
        bnz_multiply_i32(&slope, &slope, 3);
        bnz_add_bnz(&slope, &slope, &secp256k1.a);
        bnz_multiply_bnz(&slope, &slope, &tmp);
        bnz_mod_bnz(&slope, &slope, &secp256k1.p);
        bnz_multiply_bnz(&rr.x, &slope, &slope);
        bnz_subtract_bnz(&rr.x, &rr.x, &pp.x);
        bnz_subtract_bnz(&rr.x, &rr.x, &pp.x);
        bnz_mod_bnz(&rr.x, &rr.x, &secp256k1.p);
        bnz_subtract_bnz(&tmp, &pp.x, &rr.x);
        bnz_multiply_bnz(&rr.y, &slope, &tmp);
        bnz_subtract_bnz(&rr.y, &rr.y, &pp.y);
        bnz_mod_bnz(&rr.y, &rr.y, &secp256k1.p);
    } else {
        bnz_set_i32(&rr.x, 0);
        bnz_set_i32(&rr.y, 0);
    }

    bnz_set_bnz(&r->x, &rr.x);
    bnz_set_bnz(&r->y, &rr.y);

    bnz_free(&tmp);
    bnz_free(&slope);
    bnz_free(&pp.x);
    bnz_free(&pp.y);
    bnz_free(&rr.x);
    bnz_free(&rr.y);
}

void secp256k1_point_addition(const SECP256K1 secp256k1, const APT *p, const APT *q, APT *r) // r = (p + q) mod secp256k1.p
{
    bnz_t tmp, slope;

    APT pp, qq, rr;

    bnz_init(&tmp);
    bnz_init(&slope);

    bnz_init(&pp.x);
    bnz_init(&pp.y);
    bnz_init(&qq.x);
    bnz_init(&qq.y);
    bnz_init(&rr.x);
    bnz_init(&rr.y);

    bnz_set_bnz(&qq.x, &q->x);
    bnz_set_bnz(&qq.y, &q->y);
    bnz_set_bnz(&pp.x, &p->x);
    bnz_set_bnz(&pp.y, &p->y);
    bnz_set_bnz(&rr.x, &r->x);
    bnz_set_bnz(&rr.y, &r->y);

    bnz_set_i32(&slope, 0);

    bnz_mod_bnz(&pp.x, &pp.x, &secp256k1.p);
    bnz_mod_bnz(&pp.y, &pp.y, &secp256k1.p);
    bnz_mod_bnz(&qq.x, &qq.x, &secp256k1.p);
    bnz_mod_bnz(&qq.y, &qq.y, &secp256k1.p);

    if (bnz_is_zero(&pp.x) == true && bnz_is_zero(&pp.y) == true  ) {
        bnz_set_bnz(&r->x, &qq.x);
        bnz_set_bnz(&r->y, &qq.y);
        bnz_free(&tmp);
        bnz_free(&slope);
        bnz_free(&pp.x);
        bnz_free(&pp.y);
        bnz_free(&qq.x);
        bnz_free(&qq.y);
        bnz_free(&rr.x);
        bnz_free(&rr.y);
        return;
    }

    if (bnz_is_zero(&qq.x) == true && bnz_is_zero(&qq.y) == true) {
        bnz_set_bnz(&r->x, &pp.x);
        bnz_set_bnz(&r->y, &pp.y);
        bnz_free(&tmp);
        bnz_free(&slope);
        bnz_free(&pp.x);
        bnz_free(&pp.y);
        bnz_free(&qq.x);
        bnz_free(&qq.y);
        bnz_free(&rr.x);
        bnz_free(&rr.y);
        return;
    }

    if (bnz_is_zero(&qq.y) == false) {
        bnz_subtract_bnz(&tmp, &secp256k1.p, &qq.y);
        bnz_mod_bnz(&tmp, &tmp, &secp256k1.p);
    } else {
        bnz_set_i32(&tmp, 0);
    }

    if (bnz_cmp_bnz(&pp.y, &tmp) == 0 && bnz_cmp_bnz(&pp.x, &qq.x) == 0) {
        bnz_set_i32(&r->x, 0);
        bnz_set_i32(&r->y, 0);
        bnz_free(&tmp);
        bnz_free(&slope);
        bnz_free(&pp.x);
        bnz_free(&pp.y);
        bnz_free(&qq.x);
        bnz_free(&qq.y);
        bnz_free(&rr.x);
        bnz_free(&rr.y);
        return;
    }

    if (bnz_cmp_bnz(&pp.x, &qq.x) == 0 && bnz_cmp_bnz(&pp.y, &qq.y) == 0) {
        secp256k1_point_doubling(secp256k1, &pp, &rr);
    } else {
        bnz_subtract_bnz(&tmp, &pp.x, &qq.x);
        bnz_mod_bnz(&tmp, &tmp, &secp256k1.p);
        bnz_modular_multiplicative_inverse(&tmp, &tmp, &secp256k1.p);
        bnz_subtract_bnz(&slope, &pp.y, &qq.y);
        bnz_multiply_bnz(&slope, &slope, &tmp);
        bnz_mod_bnz(&slope, &slope, &secp256k1.p);
        bnz_multiply_bnz(&rr.x, &slope, &slope);
        bnz_subtract_bnz(&rr.x, &rr.x, &pp.x);
        bnz_subtract_bnz(&rr.x, &rr.x, &qq.x);
        bnz_mod_bnz(&rr.x, &rr.x, &secp256k1.p);
        bnz_subtract_bnz(&tmp, &pp.x, &rr.x);
        bnz_multiply_bnz(&rr.y, &slope, &tmp);
        bnz_subtract_bnz(&rr.y, &rr.y, &pp.y);
        bnz_mod_bnz(&rr.y, &rr.y, &secp256k1.p);
    }

    bnz_set_bnz(&r->x, &rr.x);
    bnz_set_bnz(&r->y, &rr.y);

    bnz_free(&tmp);
    bnz_free(&slope);
    bnz_free(&pp.x);
    bnz_free(&pp.y);
    bnz_free(&qq.x);
    bnz_free(&qq.y);
    bnz_free(&rr.x);
    bnz_free(&rr.y);
}

void secp256k1_scalar_multiplication(const SECP256K1 secp256k1, const APT *q, const bnz_t *m, APT *r) // r = q * m mod secp256k1.p
{
    size_t i, bits = 8 * m->size;

    APT qq;
    
    bnz_init(&qq.x);
    bnz_init(&qq.y);

    bnz_set_bnz(&qq.x, &q->x);
    bnz_set_bnz(&qq.y, &q->y);

    bnz_set_i32(&r->x, 0);
    bnz_set_i32(&r->y, 0);

    for (i = 0; i < bits; i++) {
        if (bnz_bit_set(m, i) == true) {
            secp256k1_point_addition(secp256k1, &qq, r, r);
        }
        secp256k1_point_doubling(secp256k1, &qq, &qq);
    }

    bnz_free(&qq.x);
    bnz_free(&qq.y);
}

void get_affine_from_jacobian(const SECP256K1 secp256k1, const JPT *jpt, APT *apt)
{
    bnz_t z_inv, z_inv_2, z_inv_3; // 1/z, 1/z^2, 1/z^3

    bnz_init(&z_inv);
    bnz_init(&z_inv_2);
    bnz_init(&z_inv_3);

    bnz_modular_multiplicative_inverse(&z_inv, &jpt->z, &secp256k1.p); // z_inv = modular_multiplicative_inverse(jpt.z)
    bnz_mod_bnz(&z_inv, &z_inv, &secp256k1.p); // z_inv = 1/z
    bnz_multiply_bnz(&z_inv_2, &z_inv, &z_inv); // z_inv_2 = 1/z^2
    bnz_mod_bnz(&z_inv_2, &z_inv_2, &secp256k1.p);
    bnz_multiply_bnz(&z_inv_3, &z_inv_2, &z_inv); // z_inv_3 = 1/z^3
    bnz_mod_bnz(&z_inv_3, &z_inv_3, &secp256k1.p);

    bnz_multiply_bnz(&apt->x, &jpt->x, &z_inv_2); // apt.x = jpt.x / jpt.z^2
    bnz_mod_bnz(&apt->x, &apt->x, &secp256k1.p);

    bnz_multiply_bnz(&apt->y, &jpt->y, &z_inv_3); // apt.y = jpt.y / jpt.z^3
    bnz_mod_bnz(&apt->y, &apt->y, &secp256k1.p);

    bnz_free(&z_inv); // free resources
    bnz_free(&z_inv_2);
    bnz_free(&z_inv_3);
}

void secp256k1_jacobian_point_addition(const SECP256K1 secp256k1, const JPT *p, const APT *q, JPT *r) // r = (p + q) mod secp256k1.p
{
    /*
    The "madd-2004-hmv" addition formulas:
    Assumptions: Z2=1.
    Cost: 8M + 3S + 6add + 1*2.
    Source: 2004 Hankerson Menezes Vanstone, page 91.
    Explicit formulas:
        T1 = Z1^2
        T2 = T1*Z1
        T1 = T1*X2
        T2 = T2*Y2
        T1 = T1-X1
        T2 = T2-Y1
        Z3 = Z1*T1
        T3 = T1^2
        T4 = T3*T1
        T3 = T3*X1
        T1 = 2*T3
        X3 = T2^2
        X3 = X3-T1
        X3 = X3-T4
        T3 = T3-X3
        T3 = T3*T2
        T4 = T4*Y1
        Y3 = T3-T4
    */

    bnz_t t1, t2, t3, t4;

    bnz_init(&t1);
    bnz_init(&t2);
    bnz_init(&t3);
    bnz_init(&t4);

    if (bnz_is_zero(&p->x) == true && bnz_is_zero(&p->y) == true && bnz_is_zero(&p->z) == true ) { // if this is the first addition, set r.x = q.x, r.y = q.y and r.z = 1 and return
        bnz_set_bnz(&r->x, &q->x);
        bnz_set_bnz(&r->y, &q->y);
        bnz_set_i32(&r->z, 1);
        bnz_free(&t1);
        bnz_free(&t2);
        bnz_free(&t3);
        bnz_free(&t4);
        return;
    }

    bnz_multiply_bnz(&t1, &p->z, &p->z); // T1 = Z1^2
    bnz_mod_bnz(&t1, &t1, &secp256k1.p);
    bnz_multiply_bnz(&t2, &t1, &p->z); // T2 = T1*Z1
    bnz_mod_bnz(&t2, &t2, &secp256k1.p);
    bnz_multiply_bnz(&t1, &t1, &q->x); // T1 = T1*X2
    bnz_mod_bnz(&t1, &t1, &secp256k1.p);
    bnz_multiply_bnz(&t2, &t2, &q->y); // T2 = T2*Y2
    bnz_mod_bnz(&t2, &t2, &secp256k1.p);
    bnz_subtract_bnz(&t1, &t1, &p->x); // T1 = T1-X1
    bnz_mod_bnz(&t1, &t1, &secp256k1.p);
    bnz_subtract_bnz(&t2, &t2, &p->y); // T2 = T2-Y1
    bnz_mod_bnz(&t2, &t2, &secp256k1.p);
    bnz_multiply_bnz(&r->z, &p->z, &t1); // Z3 = Z1*T1
    bnz_mod_bnz(&r->z, &r->z, &secp256k1.p);
    bnz_multiply_bnz(&t3, &t1, &t1); // T3 = T1^2
    bnz_mod_bnz(&t3, &t3, &secp256k1.p);
    bnz_multiply_bnz(&t4, &t3, &t1); // T4 = T3*T1
    bnz_mod_bnz(&t4, &t4, &secp256k1.p);
    bnz_multiply_bnz(&t3, &t3, &p->x); // T3 = T3*X1
    bnz_mod_bnz(&t3, &t3, &secp256k1.p);
    bnz_multiply_i32(&t1, &t3, 2); // T1 = 2*T3
    bnz_mod_bnz(&t1, &t1, &secp256k1.p);
    bnz_multiply_bnz(&r->x, &t2, &t2); // X3 = T2^2
    bnz_mod_bnz(&r->x, &r->x, &secp256k1.p);
    bnz_subtract_bnz(&r->x, &r->x, &t1); // X3 = X3-T1
    bnz_mod_bnz(&r->x, &r->x, &secp256k1.p);
    bnz_subtract_bnz(&r->x, &r->x, &t4); // X3 = X3-T4
    bnz_mod_bnz(&r->x, &r->x, &secp256k1.p);
    bnz_subtract_bnz(&t3, &t3, &r->x); // T3 = T3-X3
    bnz_mod_bnz(&t3, &t3, &secp256k1.p);
    bnz_multiply_bnz(&t3, &t3, &t2); // T3 = T3*T2
    bnz_mod_bnz(&t3, &t3, &secp256k1.p);
    bnz_multiply_bnz(&t4, &t4, &p->y); // T4 = T4*Y1
    bnz_mod_bnz(&t4, &t4, &secp256k1.p);
    bnz_subtract_bnz(&r->y, &t3, &t4); // Y3 = T3-T4
    bnz_mod_bnz(&r->y, &r->y, &secp256k1.p);

    bnz_free(&t1);
    bnz_free(&t2);
    bnz_free(&t3);
    bnz_free(&t4);
}

void secp256k1_jacobian_scalar_multiplication(const SECP256K1 secp256k1, const bnz_t *m, APT *r) // r = (secp256k1.G * m) mod secp256k1.p
{
    size_t i, bits = 8 * m->size;

    JPT tmp; // running total

    bnz_init(&tmp.x); // initiate x, y and z coordinates of tmp
    bnz_init(&tmp.y);
    bnz_init(&tmp.z);

    for (i = 0; i < bits; i++) { // from lsb to msb
        if (bnz_bit_set(m, i) == true) {
            secp256k1_jacobian_point_addition(secp256k1, &tmp, &secp256k1.G_doublings_mod_p[i], &tmp); // if the current bit is set, add the corresponding Secp256k1.G doubling value to the running total
        }
    }
    get_affine_from_jacobian(secp256k1, &tmp, r); // convert final JPT into the corresponding APT via the formulae: APT.x = JPT.x / JPT.z^2 and APT.y = JPT.y / JPT.z^3

    bnz_free(&tmp.x); // free resources
    bnz_free(&tmp.y);
    bnz_free(&tmp.z);
}

bool secp256k1_valid_point(const SECP256K1 secp256k1, const APT apt) // check that a given xy point is on Secp256k1 by confirming that y^2 mod Secp256k1.p = x^3 + 7 mod Secp256k1.p
{
    int32_t cmp;
    bnz_t lhs, rhs; // left hand side and right hand side of the equation

    bnz_init(&lhs); // initiate lhs and rhs
    bnz_init(&rhs);

    bnz_multiply_bnz(&lhs, &apt.y, &apt.y); // lhs = y^2
    bnz_mod_bnz(&lhs, &lhs, &secp256k1.p); // lhs = y^2 mod Secp256k1.p

    bnz_multiply_bnz(&rhs, &apt.x, &apt.x); // rhs = x^2
    bnz_multiply_bnz(&rhs, &rhs, &apt.x); // rhs = x^3
    bnz_add_i32(&rhs, &rhs, 7); // rhs = x^3 + 7
    bnz_mod_bnz(&rhs, &rhs, &secp256k1.p); // rhs = x^3 + 7 mod Secp256k1.p

    cmp = bnz_cmp_bnz(&lhs, &rhs); // compare lhs and rhs

    bnz_free(&lhs); // free resources
    bnz_free(&rhs);

    if (cmp == 0) { // lhs == rhs
        return true;
    } else { // lhs != rhs
        return false;
    }
}

bool secp256k1_valid_multiplier(const SECP256K1 secp256k1, const bnz_t *a)
{
    if (bnz_cmp_i32(a, 0) == 1 && bnz_cmp_bnz(a, &secp256k1.n) == -1) { // a is in the range 0 < k < secp256k1.n
        return true;
    } else {
        return false;
    }
}

bool secp256k1_valid_x(const SECP256K1 secp256k1, const bnz_t *x)
{
    bool result;
    const char *euler_criterion_exp_str = "57896044618658097711785492504343953926634992332820282019728792003954417335831"; // (secp256k1.p - 1) / 2
    bnz_t euler_criterion_exp, rhs, res;

    bnz_init(&euler_criterion_exp);
    bnz_init(&rhs);
    bnz_init(&res);

    bnz_set_str(&euler_criterion_exp, euler_criterion_exp_str, 10); // (secp256k1.p - 1) / 2
    secp256k1_get_rhs(secp256k1, &rhs, x); // rhs = x^3 + 7 mod secp256k1.p
    bnz_mod_pow(&res, &rhs, &euler_criterion_exp, &secp256k1.p); // res = (x^3 + 7)^((secp256k1.p - 1) / 2)) mod secp256k1.p

    if (bnz_cmp_i32(&res, 1) == 0) { // res == 1 means that x^3 + 7 mod secp256k1.p is a quadratic residue
        result = true;
    } else {
        result = false;
    }
    
    bnz_free(&euler_criterion_exp); // free resources
    bnz_free(&rhs);
    bnz_free(&res);

    return result;
}

void secp256k1_get_points_from_valid_x(const SECP256K1 secp256k1, APT *p1, APT *p2, const bnz_t *x) // given a valid x, get xy coordinates of p1 and p2
{
    const char *sqrt_exp_str = "28948022309329048855892746252171976963317496166410141009864396001977208667916"; // (secp256k1.p + 1) / 4
    bnz_t rhs, sqrt_exp;

    bnz_init(&rhs);
    bnz_init(&sqrt_exp);

    bnz_set_str(&sqrt_exp, sqrt_exp_str, 10); // (secp256k1.p + 1) / 4
    secp256k1_get_rhs(secp256k1, &rhs, x); // rhs == x^3 + 7 mod secp256k1.p == y^2 mod secp256k1.p

    bnz_set_bnz(&p1->x, x);
    bnz_set_bnz(&p2->x, x);

    if (secp256k1_valid_x(secp256k1, x) == true) {
        bnz_mod_pow(&p1->y, &rhs, &sqrt_exp, &secp256k1.p); // y1 mod secp256k1.p = (rhs^((secp256k1.p + 1) / 4)) mod secp256k1.p
        bnz_subtract_bnz(&p2->y, &secp256k1.p, &p1->y); // y2 = secp256k1.p - y
    }

    bnz_free(&rhs);
    bnz_free(&sqrt_exp);
}

/* BITCOIN GLOBAL VARIABLES */

const char bip39_wds[2048][9] = {"abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file", "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison", "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report", "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"};

/* BITCOIN FUNCTIONS */

void get_ripemd160(bnz_t *, const uint8_t *);
void get_sha256(bnz_t *, const uint8_t *);
void get_sha512(bnz_t *, const uint8_t *);
void get_ripemd160_sha256(bnz_t *, const bnz_t *, size_t);
void get_sha256_sha256(bnz_t *, const bnz_t *, size_t);
void get_256_bit_rnd(bnz_t *);
void entropy_checksum(bnz_t *);
void get_bip39_word_ids_bnz(bnz_t *, uint32_t *);
void get_bip39_word_ids_str(bnz_t *, bnz_t *, uint8_t *, char *);
uint8_t *get_mnemonic_phrase(uint32_t *);
uint8_t *get_salt(const char *);
void get_seed_from_mnemonic_phrase(bnz_t *, const char *, const char *);
void get_master_keys(bnz_t *, bnz_t *, const bnz_t *);
void get_child_normal(const SECP256K1, bnz_t *, bnz_t *, const bnz_t *, const bnz_t *, const bnz_t *, uint32_t);
void get_child_hardened(const SECP256K1, bnz_t *, bnz_t *, const bnz_t *, const bnz_t *, uint32_t);
void get_hdk_intermediate_values(const SECP256K1, const bnz_t *, const bnz_t *, char *);
void get_public_key_compressed(const SECP256K1, bnz_t *, bnz_t *);
void get_public_key(const SECP256K1, APT *, bnz_t *, bnz_t *);
void get_public_key_xy(const SECP256K1, APT *, const bnz_t *);
void get_random_master_keys(bnz_t *, bnz_t *, bnz_t *);
void get_p2pkh_address(bnz_t *, bnz_t *, uint32_t *);
void print_p2pkh_address(const bnz_t *, const uint8_t *, uint32_t);
void get_p2sh_p2wpkh_address(bnz_t *, bnz_t *);
void get_p2wpkh_address(bnz_t *, const bnz_t *);
uint32_t p2wpkh_checksum_update(uint32_t, uint8_t);
void print_p2wpkh_address(const bnz_t *, const uint8_t *);
void get_wallet_p2pkh_addresses(const SECP256K1, bnz_t *, bnz_t *);
void get_wallet_p2sh_p2wpkh_addresses(const SECP256K1, bnz_t *, bnz_t *);
void get_wallet_p2wpkh_addresses(const SECP256K1, bnz_t *, bnz_t *);

void get_ripemd160(bnz_t *res, const uint8_t *a) // res = ripemd160(a) as a bnz_t
{
    bnz_resize(res, 20, false); // prepare res.digits to receive 20 bytes of hash digest
    ripemd160(a, strlen((const char *)a), res->digits); // res.digits = ripemd160(a), big endian order
    bnz_reverse_digits(res); // convert res.digits to standard bnz_t little endian order
}

void get_sha256(bnz_t *res, const uint8_t *a) // res = sha256(a) as a bnz_t
{
    bnz_resize(res, 32, false); // prepare res.digits to receive 32 bytes of hash digest
    sha256(a, (uint64_t)strlen((const char *)a), res->digits); // res.digits = sha256(a), big endian order
    bnz_reverse_digits(res); // convert res.digits to standard bnz_t little endian order
}

void get_sha512(bnz_t *res, const uint8_t *a) // res = sha512(a) as a bnz_t
{
    bnz_resize(res, 64, false); // prepare res.digits to receive 64 bytes of hash digest
    sha512(a, (uint64_t)strlen((const char *)a), res->digits); // res.digits = sha512(a), big endian order
    bnz_reverse_digits(res); // convert res.digits to standard bnz_t little endian order
}

void get_ripemd160_sha256(bnz_t *res, const bnz_t *a, size_t len) // res = first len bytes of ripemd160(sha256(a.digits)) as a bnz_t
{
    uint8_t h1[32], h2[20];
    bnz_t aa; // aa is a mutable local copy of a 
    bnz_init(&aa); // initiate aa
    bnz_set_bnz(&aa, a); // set aa = a, standard little endian order
    bnz_reverse_digits(&aa); // convert aa.digits to big endian order
    sha256(aa.digits, aa.size, h1); // h1 = sha256(aa.digits)
    ripemd160(h1, 32, h2); // h2 = ripemd160(sha256(aa.digits))
    bnz_resize(res, len, false); // prepare res.digits to receive first len bytes of h2
    memcpy(res->digits, h2, len); // copy first len bytes of h2 into res.digits, big endian order
    bnz_reverse_digits(res); // convert res.digits to standard bnz_t little endian order
    bnz_free(&aa); // free aa resources
}

void get_sha256_sha256(bnz_t *res, const bnz_t *a, size_t len) // res = first len bytes of sha256(sha256(a.digits)) as a bnz_t
{
    uint8_t h1[32], h2[32];
    bnz_t aa; // aa is a mutable local copy of a
    bnz_init(&aa); // initiate aa
    bnz_set_bnz(&aa, a); // set aa = a, standard little endian order
    bnz_reverse_digits(&aa); // convert aa.digits to big endian order
    sha256(aa.digits, aa.size, h1); // h1 = sha256(aa.digits)
    sha256(h1, 32, h2); // h2 = sha256(sha256(aa.digits))
    bnz_resize(res, len, false); // prepare res.digits to receive the first len bytes of h2
    memcpy(res->digits, h2, len); // copy first len bytes of h2 into res.digits, big endian order
    bnz_reverse_digits(res); // convert res.digits to standard bnz_t little endian order
    bnz_free(&aa); // free aa resources
}

void get_256_bit_rnd(bnz_t *rnd) // generate 256 bit random number as a bnz_t
{
    bnz_rnd(rnd, 32);
}

void entropy_checksum(bnz_t *entropy) // append checksum byte to the lsb end of 256 bits of entropy as a bnz_t
{
    uint8_t sha256_digest[32];
    bnz_t tmp; // tmp = local mutable copy of entropy
    bnz_init(&tmp); // initiate tmp

    bnz_set_bnz(&tmp, entropy); // copy entropy into tmp
    bnz_resize(&tmp, 32, true); // ensure that tmp is 32 bytes
    bnz_reverse_digits(&tmp); // convert tmp.digits to big endian order
    sha256(tmp.digits, tmp.size, sha256_digest); // sha256_digest = sha256[tmp.digits]

    bnz_concatenate_ui8(&tmp, &tmp, sha256_digest[0], 0); // concatenate first byte of sha256_digest the the lsb end of tmp
    bnz_reverse_digits(&tmp); // convert tmp.digits to standard little endian order
    
    bnz_set_bnz(entropy, &tmp); // copy tmp back into entropy
    bnz_free(&tmp); // free tmp resources
}

void get_bip39_word_ids_bnz(bnz_t *entropy_chk, uint32_t *wd_ids) // convert 33 bytes of entropy + checksum as a bnz_t into 24 numbers of 11 bits
{
    size_t i;
    bnz_t tmp;
    bnz_init(&tmp);

    bnz_set_bnz(&tmp, entropy_chk);
    bnz_resize(&tmp, 33, true);
    bnz_reverse_digits(&tmp);

    for (i = 0; i < 3; i++) {
        wd_ids[(i * 8) + 0] = ((((uint32_t)tmp.digits[(i * 11) + 0]) << 3) & 2040) + ((((uint32_t)tmp.digits[(i * 11) + 1]) >> 5) & 7);
        wd_ids[(i * 8) + 1] = ((((uint32_t)tmp.digits[(i * 11) + 1]) << 6) & 1984) + ((((uint32_t)tmp.digits[(i * 11) + 2]) >> 2) & 63);
        wd_ids[(i * 8) + 2] = ((((uint32_t)tmp.digits[(i * 11) + 2]) << 9) & 1536) + ((((uint32_t)tmp.digits[(i * 11) + 3]) << 1) & 510) + ((((uint32_t)tmp.digits[(i * 11) + 4]) >> 7) & 1);
        wd_ids[(i * 8) + 3] = ((((uint32_t)tmp.digits[(i * 11) + 4]) << 4) & 2032) + ((((uint32_t)tmp.digits[(i * 11) + 5]) >> 4) & 15);
        wd_ids[(i * 8) + 4] = ((((uint32_t)tmp.digits[(i * 11) + 5]) << 7) & 1920) + ((((uint32_t)tmp.digits[(i * 11) + 6]) >> 1) & 127);
        wd_ids[(i * 8) + 5] = ((((uint32_t)tmp.digits[(i * 11) + 6]) << 10) & 1024) + ((((uint32_t)tmp.digits[(i * 11) + 7]) << 2) & 2044) + ((((uint32_t)tmp.digits[(i * 11) + 8]) >> 6) & 3);
        wd_ids[(i * 8) + 6] = ((((uint32_t)tmp.digits[(i * 11) + 8]) << 5) & 2016) + ((((uint32_t)tmp.digits[(i * 11) + 9]) >> 3) & 31);
        wd_ids[(i * 8) + 7] = ((((uint32_t)tmp.digits[(i * 11) + 9]) << 8) & 1792) + ((((uint32_t)tmp.digits[(i * 11) + 10])));
    }

    bnz_free(&tmp);
}

void get_bip39_word_ids_str(bnz_t *entropy_chk, bnz_t *entropy, uint8_t *chk, char *mnemonic_str) // convert 24 words into 32 bytes of entropy + 1 byte of checksum
{
    size_t i = 0, j;
    char sha256_digest[32], *tok = strtok(mnemonic_str, " "); // split mnemonic string into an array of BIP39 words
    uint32_t wd_ids[24];

    bnz_resize(entropy_chk, 33, false);

    while (tok != NULL) { // traverse array
        for (j = 0; j < 2048; j++) { // search BIP39 list for matches
            if (!strcmp(tok, bip39_wds[j])) { // match found
                wd_ids[i++] = j; // record id
                break; // exit loop as soon as match found
            }
        }
        tok = strtok(NULL, " "); // next array member
    }

    for (i = 0; i < 3; i++) {
        entropy_chk->digits[(i * 11) + 0] = (wd_ids[(i * 8) + 0] >> 3) & 255;
        entropy_chk->digits[(i * 11) + 1] = (((wd_ids[(i * 8) + 0] & 7) << 5) + (wd_ids[(i * 8) + 1] >> 6)) & 255;
        entropy_chk->digits[(i * 11) + 2] = (((wd_ids[(i * 8) + 1] & 63) << 2) + (wd_ids[(i * 8) + 2] >> 9)) & 255;
        entropy_chk->digits[(i * 11) + 3] = (wd_ids[(i * 8) + 2] >> 1) & 255;
        entropy_chk->digits[(i * 11) + 4] = (((wd_ids[(i * 8) + 2] & 1) << 7) + (wd_ids[(i * 8) + 3] >> 4)) & 255;
        entropy_chk->digits[(i * 11) + 5] = (((wd_ids[(i * 8) + 3] & 15) << 4) + (wd_ids[(i * 8) + 4] >> 7)) & 255;
        entropy_chk->digits[(i * 11) + 6] = (((wd_ids[(i * 8) + 4] & 127) << 1) + (wd_ids[(i * 8) + 5] >> 10)) & 255;
        entropy_chk->digits[(i * 11) + 7] = (wd_ids[(i * 8) + 5] >> 2) & 255;
        entropy_chk->digits[(i * 11) + 8] = (((wd_ids[(i * 8) + 5] & 3) << 6) + (wd_ids[(i * 8) + 6] >> 5)) & 255;
        entropy_chk->digits[(i * 11) + 9] = (((wd_ids[(i * 8) + 6] & 31) << 3) + (wd_ids[(i * 8) + 7] >> 8)) & 255;
        entropy_chk->digits[(i * 11) + 10] = wd_ids[(i * 8) + 7] & 255;
    }

    bnz_set_bnz(entropy, entropy_chk); // copy 33 bytes of entropy_chk into entropy
    bnz_resize(entropy, 32, true); // resize entropy to 32 bytes of entropy
    sha256(entropy->digits, 32, sha256_digest); // get SHA256 hash digest of entropy->digits
    *chk = sha256_digest[0]; // set chk to first byte of SHA256 hash digest
    bnz_reverse_digits(entropy); // convert to little
    bnz_reverse_digits(entropy_chk); // endian order
}

uint8_t *get_mnemonic_phrase(uint32_t *wd_ids) // generate mnemonic string of 24 words
{
    uint8_t *mnemonic_str = NULL;
    int i, len = 0;

    for (i = 0; i < 24; i++) {
        len += strlen(bip39_wds[wd_ids[i]]);
    }

    mnemonic_str = init_uint8_array(len + 24 /* 23 chars for the spaces between the individual mnemonic words + one char for the null terminator */);
    if (!mnemonic_str) {
        return NULL;
    }

    for (i = 0; i < 23; i++) {
        sprintf(mnemonic_str + strlen(mnemonic_str), "%s ", bip39_wds[wd_ids[i]]);
    }

    sprintf(mnemonic_str + strlen(mnemonic_str), "%s", bip39_wds[wd_ids[23]]);

    return(mnemonic_str);
}

uint8_t *get_salt(const char *passphrase) // generate salt string from passphrase
{
    uint8_t *salt = NULL;

    salt = init_uint8_array(strlen("mnemonic") + strlen(passphrase) + sizeof(uint32_t)); // initiate salt to hold "mnemonic" concatenated with passphrase and 4 bytes of uint32_t
    if (!salt) {
        return NULL;
    }

    sprintf((char *)salt, "mnemonic%s", passphrase); // set salt = "mnemonic" concatenated with passphrase
    salt[strlen("mnemonic") + strlen(passphrase) + sizeof(uint32_t) - 1] = 1; // set the value of the last byte of salt to 1

    return salt;
}

void get_seed_from_mnemonic_phrase(bnz_t *seed, const char *mnemonic, const char *passphrase) // generate 64 byte seed from mnemonic string and optional passphrase
{
    uint8_t tmp[64], *salt = NULL;
    size_t i, j;

    bnz_resize(seed, 64, false); // ensure that seed is 64 bytes

    salt = get_salt(passphrase); // salt = "mnemonic" concatenated with passphrase and the value 1 formatted as a uint32_t, strlen(salt) = strlen("mnemonic") + strlen(passphrase) + sizeof(uint32_t)
    if (!salt) {
        return;
    }

    hmac_sha512(mnemonic, strlen(mnemonic), salt, strlen("mnemonic") + strlen(passphrase) + sizeof(uint32_t), tmp, 64); // tmp = first hmac(mnemonic, salt)
    memcpy(seed->digits, tmp, 64); // set seed = result of first hmac process

    for (i = 1; i < 2048; i++) { // repeat 2048 times
        hmac_sha512(mnemonic, strlen(mnemonic), tmp, 64, tmp, 64);  // tmp = hmac(mnemonic, tmp)
        for (j = 0; j < 64; j++) {
            seed->digits[j] = tmp[j] ^ seed->digits[j]; // xor each byte of current seed.digits with corresponding byte of current tmp
        }
    }

    bnz_reverse_digits(seed); // convert seed.digits to standard little endian order

    free(salt); // free resources
}

void get_master_keys(bnz_t *master_private_key, bnz_t *master_chain_code, const bnz_t *seed) // generate 32 byte master private key and 32 byte master chain_code
{
    uint8_t mac[64];

    bnz_t tmp;
    bnz_init(&tmp);

    bnz_set_bnz(&tmp, seed); // copy seed to tmp

    bnz_resize(&tmp, 64, true); // ensure that tmp is 64 bytes
    bnz_reverse_digits(&tmp); // convert tmp.digits to big endian order
    hmac_sha512("Bitcoin seed", 12, tmp.digits, tmp.size, mac, 64); // generate 64 byte MAC from tmp.digits and the initial key "Bitcoin seed"

    bnz_resize(master_private_key, 32, false); // prepare master_private_key to receive the first 32 bytes of the MAC
    memcpy(master_private_key->digits, mac, 32); // copy the first 32 bytes of the MAC into master_private_key
    bnz_reverse_digits(master_private_key); // convert master_private_key.digits to default little endian order

    bnz_resize(master_chain_code, 32, false); // prepare master_chain_code to receive the last 32 bytes of the MAC
    memcpy(master_chain_code->digits, mac + 32, 32); // copy the last 32 bytes of the MAC into master_chain_code
    bnz_reverse_digits(master_chain_code); // convert master_chain_code.digits to default little endian order

    bnz_free(&tmp);
}

void get_child_normal(const SECP256K1 secp256k1, bnz_t *child_private_key, bnz_t *child_chain_code, const bnz_t *parent_private_key, const bnz_t *parent_chain_code, const bnz_t *parent_public_key_compressed, uint32_t index_num)
{
    uint8_t mac[64];
    bnz_t index, tmp1, tmp2;

    bnz_init(&index);
    bnz_init(&tmp1);
    bnz_init(&tmp2);

    bnz_set_ui32(&index, index_num);
    bnz_set_bnz(&tmp1, parent_chain_code);
    bnz_set_bnz(&tmp2, parent_public_key_compressed);

    bnz_resize(&index, 4, true);
    bnz_resize(&tmp1, 32, true);
    bnz_resize(&tmp2, 33, true);

    bnz_concatenate_bnz(&tmp2, &tmp2, &index, 1);

    bnz_reverse_digits(&tmp1);
    bnz_reverse_digits(&tmp2);

    hmac_sha512(tmp1.digits, tmp1.size, tmp2.digits, tmp2.size, mac, 64);

    bnz_resize(child_private_key, 32, false);
    bnz_resize(child_chain_code, 32, false);

    memcpy(child_private_key->digits, mac, 32);
    memcpy(child_chain_code->digits, mac + 32, 32);

    bnz_reverse_digits(child_private_key);
    bnz_add_bnz(child_private_key, child_private_key, parent_private_key);
    bnz_mod_bnz(child_private_key, child_private_key, &secp256k1.n);

    bnz_reverse_digits(child_chain_code);

    bnz_free(&index);
    bnz_free(&tmp1);
    bnz_free(&tmp2);
}

void get_child_hardened(const SECP256K1 secp256k1, bnz_t *child_private_key, bnz_t *child_chain_code, const bnz_t *parent_private_key, const bnz_t *parent_chain_code, uint32_t index_num)
{
    uint8_t mac[64];
    bnz_t index, tmp1, tmp2;

    bnz_init(&index);
    bnz_init(&tmp1);
    bnz_init(&tmp2);

    bnz_set_ui32(&index, index_num < 2147483648 ? 2147483648 + index_num : index_num);
    bnz_set_bnz(&tmp1, parent_chain_code);
    bnz_set_bnz(&tmp2, parent_private_key);

    bnz_resize(&index, 4, true);
    bnz_resize(&tmp1, 32, true);
    bnz_resize(&tmp2, 32, true);

    bnz_concatenate_ui8(&tmp2, &tmp2, 0, 0);
    bnz_concatenate_bnz(&tmp2, &tmp2, &index, 1);

    bnz_reverse_digits(&tmp1);
    bnz_reverse_digits(&tmp2);

    hmac_sha512(tmp1.digits, tmp1.size, tmp2.digits, tmp2.size, mac, 64);

    bnz_resize(child_private_key, 32, false);
    bnz_resize(child_chain_code, 32, false);

    memcpy(child_private_key->digits, mac, 32);
    memcpy(child_chain_code->digits, mac + 32, 32);

    bnz_reverse_digits(child_private_key);
    bnz_add_bnz(child_private_key, child_private_key, parent_private_key);
    bnz_mod_bnz(child_private_key, child_private_key, &secp256k1.n);

    bnz_reverse_digits(child_chain_code);

    bnz_free(&index);
    bnz_free(&tmp1);
    bnz_free(&tmp2);
}

void get_hdk_intermediate_values(const SECP256K1 secp256k1, const bnz_t *master_private_key, const bnz_t *master_chain_code, char *hdk_str)
{
    char *tok = strtok(hdk_str, "/"), display_str[32]; // split str into an array of indicies
    uint32_t index, depth = 0;

    bnz_t parent_private_key, parent_chain_code, parent_public_key_compressed, child_private_key, child_chain_code, child_public_key_compressed;

    bnz_init(&parent_private_key);
    bnz_init(&parent_chain_code);
    bnz_init(&parent_public_key_compressed);
    bnz_init(&child_private_key);
    bnz_init(&child_chain_code);
    bnz_init(&child_public_key_compressed);

    bnz_set_bnz(&parent_private_key, master_private_key);
    bnz_set_bnz(&parent_chain_code, master_chain_code);

    sprintf(display_str, "m");

    if (strcmp(tok, "m") == 0) {
        tok = strtok(NULL, "/"); // get first array member
        while (tok != NULL) { // traverse array

            sprintf(display_str + strlen(display_str), "/"); // update display
            sprintf(display_str + strlen(display_str), tok); // string

            depth++; // increment depth
            index = atoi(tok); // extract index from tok, ignoring any "'" indicating hardened child 

            get_public_key_compressed(secp256k1, &parent_public_key_compressed, &parent_private_key); // get parent compressed public key for calculating normal child 

            if (tok[strlen(tok) - 1] == '\'') { // check for presence of "'" indicating hardened child
                if (index < 2147483648) index += 2147483648;
                get_child_hardened(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, index); // if last char of tok is "'", get hardened child
            } else {
                get_child_normal(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, &parent_public_key_compressed, index); // if last char of tok is not "'", get normal child
            }

            get_public_key_compressed(secp256k1, &child_public_key_compressed, &child_private_key); // get compressed public key from child private key

            // print results
            printf("%s\n", display_str);
            bnz_print(&parent_private_key, 16, "PARENT PRIVATE KEY: ");
            bnz_print(&parent_chain_code, 16, "PARENT CHAIN CODE: ");
            bnz_print(&child_private_key, 16, "CHILD PRIVATE KEY: ");
            bnz_print(&child_chain_code, 16, "CHILD CHAIN CODE: ");
            printf("\n");

            // prepare next iteration by setting parent private key and parent chain code to current child private key and child chain code
            bnz_set_bnz(&parent_private_key, &child_private_key);
            bnz_set_bnz(&parent_chain_code, &child_chain_code);

            tok = strtok(NULL, "/"); // next array member
        }
    }

    bnz_free(&parent_private_key);
    bnz_free(&parent_chain_code);
    bnz_free(&parent_public_key_compressed);
    bnz_free(&child_private_key);
    bnz_free(&child_chain_code);
    bnz_free(&child_public_key_compressed);
}

void get_public_key_compressed(const SECP256K1 secp256k1, bnz_t *public_key_compressed, bnz_t *private_key)
{
    APT public_key;

    bnz_init(&public_key.x);
    bnz_init(&public_key.y);

    secp256k1_jacobian_scalar_multiplication(secp256k1, private_key, &public_key);

    bnz_resize(&public_key.x, 32, true);

    if (bnz_bit_set(&public_key.y, 0) == false) {
        bnz_concatenate_ui8(public_key_compressed, &public_key.x, 2, 0);
    } else { // odd y
        bnz_concatenate_ui8(public_key_compressed, &public_key.x, 3, 0);
    }
    
    bnz_free(&public_key.x);
    bnz_free(&public_key.y);
}

void get_public_key(const SECP256K1 secp256k1, APT *public_key, bnz_t *public_key_compressed, bnz_t *private_key) // generate public key from private key
{
    secp256k1_jacobian_scalar_multiplication(secp256k1, private_key, public_key); // public_key = (secp256k1.G * private_key) mod secp256k1.p

    bnz_resize(&public_key->x, 32, true); // ensure that the compressed public key is 32 bytes long before concatenation with the even y / odd y byte

    if (bnz_bit_set(&public_key->y, 0) == false) { // even y
        bnz_concatenate_ui8(public_key_compressed, &public_key->x, 2, 0); // prepend 2
    } else { // odd y
        bnz_concatenate_ui8(public_key_compressed, &public_key->x, 3, 0); // prepend 3
    }
}

void get_public_key_xy(const SECP256K1 secp256k1, APT *public_key, const bnz_t *public_key_compressed) // regenerate public key point on secp256k1 from compressed public key
{
    const char *exp_str = "28948022309329048855892746252171976963317496166410141009864396001977208667916"; // (secp256k1.p + 1) / 4
    uint8_t parity_byte = public_key_compressed->digits[public_key_compressed->size - 1]; // byte at msb encodes the parity of y: parity_byte = 0x02 for even y, parity_byte = 0x03 for odd y
    bnz_t exp, y_sq;

    bnz_init(&exp);
    bnz_init(&y_sq);

    /*

    In this function we wish to regenerate the x,y coordinates of a point on secp256k1 from a compressed public key, which is
    the x coordinate of the point concatenated (at the msb end) with a byte of value 2 or 3, depending on whether the value of
    y is even (0x02) or odd (0x03).

    Generating the y coordinate of a point on secp256k1, given the corresponding x coordinate, leverages a nice property of
    secp256k1 which is that, given y^2 mod secp256k1.p (easily calculated from x given the formula of secp256k1: y^2 = x^3 + 7),
    we can calculate y as follows:

        y mod secp256k1.p = (y_sq^((secp256k1.p + 1) / 4)) mod secp256k1.p

    In this function we use a pre-calculated value of (secp256k1.p + 1) / 4.

    */

    bnz_set_str(&exp, exp_str, 10); // (secp256k1.p + 1) / 4

    bnz_set_bnz(&public_key->x, public_key_compressed); // public_key.x = compressed public key
    bnz_resize(&public_key->x, public_key->x.size - 1, true); // public_key.x = decompressed public key, byte at msb end removed

    bnz_multiply_bnz(&y_sq, &public_key->x, &public_key->x); // y_sq = public_key.x^2
    bnz_multiply_bnz(&y_sq, &y_sq, &public_key->x); // y_sq = public_key.x^3
    bnz_add_i32(&y_sq, &y_sq, 7); // y_sq = public_key.x^3 + 7
    bnz_mod_bnz(&y_sq, &y_sq, &secp256k1.p); // y_sq mod secp256k1.p = (public_key.x^3 + 7) mod secp256k1.p

    bnz_mod_pow(&public_key->y, &y_sq, &exp, &secp256k1.p); // y mod secp256k1.p = (y_sq^((secp256k1.p + 1) / 4)) mod secp256k1.p

    if ((parity_byte == 2 && bnz_bit_set(&public_key->y, 0) == true) || (parity_byte == 3 && bnz_bit_set(&public_key->y, 0) == false)) { // mismatched parity_byte and y parity
        bnz_subtract_bnz(&public_key->y, &secp256k1.p, &public_key->y); // y = secp256k1.p - y, negation of y mod p
    }

    bnz_free(&exp);
    bnz_free(&y_sq);
}

void get_random_master_keys(bnz_t *entropy, bnz_t *master_private_key, bnz_t *master_chain_code) // NOT SECURE use random 256 bit entropy to generate master private key and master chain code
{
    char *mnemonic = NULL;
    uint32_t wd_ids[24];
    bnz_t tmp, seed;

    bnz_init(&tmp);
    bnz_init(&seed);

    get_256_bit_rnd(entropy); // generate 32 bytes of random entropy
    bnz_set_bnz(&tmp, entropy); // copy entropy into tmp

    entropy_checksum(&tmp); // calculate and append checksum byte to copy of entropy, 33 byte result
    get_bip39_word_ids_bnz(&tmp, wd_ids); // get the ids of the 24 BIP39 words from the 33 byte tmp
    mnemonic = get_mnemonic_phrase(wd_ids); // generate mnemonic phrase string from BIP39 word ids
    get_seed_from_mnemonic_phrase(&seed, mnemonic, ""); // generate 64 byte seed from mnemonic phrase
    get_master_keys(master_private_key, master_chain_code, &seed); // generate master private key and master chain code from seed

    free(mnemonic);
    bnz_free(&tmp);
    bnz_free(&seed);
}

void get_p2pkh_address(bnz_t *p2pkh, bnz_t *public_key_compressed, uint32_t *p2pkh_leading_zeros) // get p2pkh address from compressed public key
{
    bnz_t fingerprint;
    bnz_init(&fingerprint);
    get_ripemd160_sha256(p2pkh, public_key_compressed, 20); // set p2pkh to ripemd160(sha256(public_key_compressed.digits)), p2pkh->size = 20
    bnz_concatenate_ui8(p2pkh, p2pkh, 0, 0); // concatenate 0 byte to msb end of p2pkh.digits, p2pkh->size = 21
    get_sha256_sha256(&fingerprint, p2pkh, 4); // set fingerprint to first four bytes of sha256(sha256(p2pkh.digits))
    bnz_concatenate_bnz(p2pkh, p2pkh, &fingerprint, 1); // concatenate fingerprint to lsb end of p2pkh, p2pkh->size = 25
    bnz_trim(p2pkh); // remove zero value bytes from msb end of p2pkh, p2pkh->size reduces by at least 1
    (*p2pkh_leading_zeros) = 25 - p2pkh->size; // number of leading zeros = 25 - p2pkh->size after trimming leading zeros
    bnz_free(&fingerprint); // free fingerprint
}

void print_p2pkh_address(const bnz_t *p2pkh, const uint8_t *str, uint32_t p2pkh_leading_zeros)
{
    uint8_t *full_string = NULL, *p2pkh_base58_str = NULL;
    uint32_t i, len;
    bnz_t tmp;
    bnz_init(&tmp);
    bnz_set_bnz(&tmp, p2pkh); // tmp = local mutable copy of p2pkh bnz_t with tmp.digits in standard little endian order 
    bnz_reverse_digits(&tmp); // convert tmp.digits to big endian order

    p2pkh_base58_str = get_base_n_str(&tmp, 58, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", &len); // get base58 format string of non-zero integer part of p2pkh
    if (!p2pkh_base58_str) {
        return;
    }

    full_string = init_uint8_array(strlen(str) + strlen(p2pkh_base58_str) + p2pkh_leading_zeros + 1); // prepare full string to receive str, leading zeros, and base58 format non-zero integer part of p2pkh
    if (!full_string) {
        return;
    }

    sprintf(full_string, "%s", str); // add str
    for (i = 0; i  < p2pkh_leading_zeros; i++) {
        sprintf(full_string + strlen(full_string), "1"); // add leading zeros in base58 as "1" characters
    }
    sprintf(full_string + strlen(full_string), "%s", p2pkh_base58_str); // add non-zero integer part of p2pkh

    printf("%s\n", full_string); // print final string

    free(full_string);
    free(p2pkh_base58_str);
    bnz_free(&tmp);
}

void get_p2sh_p2wpkh_address(bnz_t *p2sh_p2wpkh, bnz_t *public_key_compressed)
{
    bnz_t fingerprint, pub_key_hash;
    bnz_init(&fingerprint);
    bnz_init(&pub_key_hash);
    get_ripemd160_sha256(&pub_key_hash, public_key_compressed, 20); // set pub_key_hash to ripemd160(sha256(public_key_compressed.digits))
    bnz_concatenate_ui8(&pub_key_hash, &pub_key_hash, 20, 0); // concatenate 0x14 to msb end of pub_key_hash
    bnz_concatenate_ui8(&pub_key_hash, &pub_key_hash, 0, 0); // concatenate 0x0 to msb end of pub_key_hash
    get_ripemd160_sha256(p2sh_p2wpkh, &pub_key_hash, 20); // set p2sh_p2wpkh to ripemd160(sha256(pub_key_hash.digits))
    bnz_concatenate_ui8(p2sh_p2wpkh, p2sh_p2wpkh, 5, 0); // concatenate 5 byte to msb end of p2sh_p2wpkh.digits
    get_sha256_sha256(&fingerprint, p2sh_p2wpkh, 4); // set fingerprint to first four bytes of sha256(sha256(p2sh_p2wpkh.digits))
    bnz_concatenate_bnz(p2sh_p2wpkh, p2sh_p2wpkh, &fingerprint, 1); // concatenate fingerprint to lsb end of p2sh_p2wpkh
    bnz_trim(p2sh_p2wpkh); // remove zero value bytes from msb end of p2sh_p2wpkh
    bnz_free(&fingerprint); // free resources
}

void get_p2wpkh_address(bnz_t *p2wpkh, const bnz_t *public_key_compressed)
{
    const char *bech32_alpha = "qpzry9x8gf2tvdw0s3jn54khce6mua7l", *witness_initial_str = "rrqzrqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
    char witness_program_str[45] = {0}, p2wpkh_str[27] = {0}, chk_str[7] = {0};
    uint8_t *scriptpubkey_bech32_str = NULL;
    uint32_t i, len, chk = 1;

    bnz_t tmp;
    bnz_init(&tmp);

    get_ripemd160_sha256(&tmp, public_key_compressed, 20); // tmp = ripemd160(sha256(public_key_compressed)), 20 bytes, little endian order
    bnz_reverse_digits(&tmp); // convert tmp.digits to big endian order in preparation for generating the corresponding bech32 format string

    scriptpubkey_bech32_str = get_base_n_str(&tmp, 32, bech32_alpha, &len); // scriptpubkey_bech32_str = tmp.digits in bech32 format, big endian order
    if (!scriptpubkey_bech32_str) {
        return;
    }

    /*

    The witness program comprises four elements: expanded hrp + version + scriptpubkey in bech32 + padding.

    Expanded hrp = "rrqzr", the prefix to witness program.

    Derivation:

    hrp = "bc" = 99 98 in ascii = 01100010 01100011 in binary
    Expanded hrp = 00011 00011 00000 00010 00011, top 3 bits of 'b' and 'c' in ascii padded left to 5 bits + 5 zero bits separator + bottom 5 bits of 'b' and 'c' in ascii
    Numerical values of expanded hrp = 3, 3, 0, 2, 3
    Bech32 encoding of expanded hrp = r, r, q, z, r

    The expanded hrp is followed by a 'q' zero digit representing the segwit version number.

    "qqqqqq" = 6 zero digits in Bech32.

    */

    sprintf((char *)witness_program_str, "%s", (const char *)witness_initial_str); // witness_program_str = "rrqzrq" + 32 zeros to allow for offset in case strlen(scriptpubkey_bech32_str) < 32
    sprintf((char *)witness_program_str + 38 - strlen((const char *)scriptpubkey_bech32_str), "%sqqqqqq", (const char *)scriptpubkey_bech32_str); // witness_program_str = "rrqzrq" + zero padding if required + scriptpubkey_bech32_str + "qqqqqq"

    //get checksum, occupying 30 bits of uint32_t
    for (i = 0; i < strlen((const char *)witness_program_str); i++) {
        chk = p2wpkh_checksum_update(chk, char_32[(uint8_t)witness_program_str[i]]); // dgt = decimal value (0 - 31) corresponding to bech32 character
    }
    chk ^= 1; // finalise checksum, xor with 1 means standard segwit

    // convert checksum from 30 bits formatted as uint32_t (big endian order) into 6 x 5 bit digits in bech32, stored as uint8_t array, little endian order
    for (i = 0; i < 6; i++) {
        chk_str[i] = bech32_alpha[(chk >> ((5 - i) * 5)) & 31];
    }

    sprintf(p2wpkh_str, "%s%s", (const char *)scriptpubkey_bech32_str, (const char *)chk_str); // numerical part of address = scriptpubkey_bech32_str (20) + checksum (6)

    bnz_set_str(p2wpkh, (const char *)p2wpkh_str, 32); // convert p2wpkh_str (numerical part of standard segwit address) into standard bnz_t, will be printed with non-bech32 prefix "bc1q"

    // free resources
    free(scriptpubkey_bech32_str);
    bnz_free(&tmp);
}

uint32_t p2wpkh_checksum_update(uint32_t chk, uint8_t dgt)
{
    uint8_t top = (chk >> 25); // top = top 5 bits of current chk, formatted as uint8_t
    uint32_t btm = (chk & 33554431) << 5; // btm = bottom 25 bits of current chk (from bitwise AND with 0x1ffffff) padded with 5 zeros at lsb end, formatted as uint32_t
    btm ^= dgt; // xor btm with current digit of witness program, formatted as uint8_t
    if ((top >> 0) & 1) btm ^= 996825010; // if 1st bit of top is set, xor btm with 1st constant (0x3b6a57b2)
    if ((top >> 1) & 1) btm ^= 642813549; // if 2nd bit of top is set, xor btm with 2nd constant (0x26508e6d)
    if ((top >> 2) & 1) btm ^= 513874426; // if 3rd bit of top is set, xor btm with 3rd constant (0x1ea119fa)
    if ((top >> 3) & 1) btm ^= 1027748829; // if 4th bit of top is set, xor btm with 4th constant (0x3d4233dd)
    if ((top >> 4) & 1) btm ^= 705979059; // if 5th bit of top is set, xor btm with 5th constant (0x2a1462b3)
    return btm; // return btm, the new value of chk, formatted as uint32_t
}

void print_p2wpkh_address(const bnz_t *p2wpkh, const uint8_t *str)
{
    uint8_t *full_string = NULL, *p2wpkh_bech32_str = NULL;
    uint32_t len;

    /*
    
    Segwit P2WPKH addresses have a prefix "bc1q" which contains non-Bech32 characters
    and is concatenated with the numercial part of the address.
    
    The numerical part is itself a concatenation of the RIPEMD160-SHA256 double
    hash of the compressed public key encoded in Bech32, and a 6 character checksum,
    also formatted in Bech32.

    In bitcoin_math, the numerical part is treated as a number and is stored in
    a standard bnz_t, and the prefix is only added when the Segwit P2WPKH address is
    printed to the screen.

    However, RIPEMD160 digests (and their Bech32 encodings) can have zeros at the
    msb end, causing issues with printing when the numerical part is treated as a
    number because leading zeros are not printed.

    bitcoin_math therefore incorporates this dedicated print function for Segwit
    P2WPKH addresses which ensures that, where the numerical part of the address
    has one or more zeros at the msb end, it is padded with 'q' characters
    (representing zeros in Bech32) before the prefix is appended. 
    
    */

    bnz_t tmp;
    bnz_init(&tmp);
    bnz_set_bnz(&tmp, p2wpkh); // tmp = local mutable copy of p2wpkh bnz_t with tmp.digits in standard little endian order 
    bnz_reverse_digits(&tmp); // convert tmp.digits to big endian order

    full_string = init_uint8_array(strlen(str) + 43); // prepare full_string to receive str + 42 characters + null terminator
    if (!full_string) {
        return;
    }

    p2wpkh_bech32_str = get_base_n_str(&tmp, 32, "qpzry9x8gf2tvdw0s3jn54khce6mua7l", &len); // get bech32 string encoding of p2wpkh_bech32_str in big endian order
    if (!p2wpkh_bech32_str) {
        free(full_string);
        return;
    }

    sprintf(full_string, "%sbc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", str); // full_string = str + "bc1q" + 38 x 'q' + null terminator
    sprintf(full_string + strlen(str) + 42 - len, p2wpkh_bech32_str); // concatenate Bech32 string with appropriate offset to ensure 'q' padding at msb end if required

    printf("%s\n", full_string); // print final string

    free(full_string);
    free(p2wpkh_bech32_str);
    bnz_free(&tmp);
}

void get_wallet_p2pkh_addresses(const SECP256K1 secp256k1, bnz_t *master_private_key, bnz_t *master_chain_code)
{
    uint32_t i, p2pkh_leading_zeros;

    bnz_t parent_private_key, parent_chain_code, parent_public_key_compressed, child_private_key, child_chain_code, child_public_key_compressed, p2pkh;

    bnz_init(&parent_private_key);
    bnz_init(&parent_chain_code);
    bnz_init(&parent_public_key_compressed);
    bnz_init(&child_private_key);
    bnz_init(&child_chain_code);
    bnz_init(&child_public_key_compressed);
    bnz_init(&p2pkh);

    // m/44'
    bnz_set_bnz(&parent_private_key, master_private_key);
    bnz_set_bnz(&parent_chain_code, master_chain_code);
    get_child_hardened(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, 44);

    // m/44'/0'
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_child_hardened(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, 0);

    // m/44'/0'/0'
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_child_hardened(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, 0);

    // m/44'/0'/0'/0
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_public_key_compressed(secp256k1, &parent_public_key_compressed, &parent_private_key);
    get_child_normal(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, &parent_public_key_compressed, 0);

    // m/44'/0'/0'/0/0 to m/44'/0'/0'/0/19
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_public_key_compressed(secp256k1, &parent_public_key_compressed, &parent_private_key);
    for (i = 0; i < 20; i++) {
        get_child_normal(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, &parent_public_key_compressed, i);
        get_public_key_compressed(secp256k1, &child_public_key_compressed, &child_private_key);
        get_p2pkh_address(&p2pkh, &child_public_key_compressed, &p2pkh_leading_zeros);
        printf("m/44'/0'/0'/0/%d: ", i);
        print_p2pkh_address(&p2pkh, "", p2pkh_leading_zeros);
    }

    printf("\n");

    bnz_free(&parent_private_key);
    bnz_free(&parent_chain_code);
    bnz_free(&parent_public_key_compressed);
    bnz_free(&child_private_key);
    bnz_free(&child_chain_code);
    bnz_free(&p2pkh);
}

void get_wallet_p2sh_p2wpkh_addresses(const SECP256K1 secp256k1, bnz_t *master_private_key, bnz_t *master_chain_code)
{
    uint32_t i;
    
    bnz_t parent_private_key, parent_chain_code, parent_public_key_compressed, child_private_key, child_chain_code, child_public_key_compressed, p2sh_p2wpkh;

    bnz_init(&parent_private_key);
    bnz_init(&parent_chain_code);
    bnz_init(&parent_public_key_compressed);
    bnz_init(&child_private_key);
    bnz_init(&child_chain_code);
    bnz_init(&child_public_key_compressed);
    bnz_init(&p2sh_p2wpkh);

    // m/49'
    bnz_set_bnz(&parent_private_key, master_private_key);
    bnz_set_bnz(&parent_chain_code, master_chain_code);
    get_child_hardened(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, 49);

    // m/49'/0'
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_child_hardened(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, 0);

    // m/49'/0'/0'
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_child_hardened(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, 0);

    // m/49'/0'/0'/0
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_public_key_compressed(secp256k1, &parent_public_key_compressed, &parent_private_key);
    get_child_normal(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, &parent_public_key_compressed, 0);

    // m/49'/0'/0'/0/0 to m/49'/0'/0'/0/19
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_public_key_compressed(secp256k1, &parent_public_key_compressed, &parent_private_key);
    for (i = 0; i < 20; i++) {
        get_child_normal(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, &parent_public_key_compressed, i);
        get_public_key_compressed(secp256k1, &child_public_key_compressed, &child_private_key);
        get_p2sh_p2wpkh_address(&p2sh_p2wpkh, &child_public_key_compressed);
        printf("m/49'/0'/0'/0/%d: ", i);
        bnz_print(&p2sh_p2wpkh, 58, "");
    }
    printf("\n");

    bnz_free(&parent_private_key);
    bnz_free(&parent_chain_code);
    bnz_free(&parent_public_key_compressed);
    bnz_free(&child_private_key);
    bnz_free(&child_chain_code);
    bnz_free(&p2sh_p2wpkh);
}

void get_wallet_p2wpkh_addresses(const SECP256K1 secp256k1, bnz_t *master_private_key, bnz_t *master_chain_code)
{
    uint32_t i;
    
    bnz_t parent_private_key, parent_chain_code, parent_public_key_compressed, child_private_key, child_chain_code, child_public_key_compressed, p2wpkh;

    bnz_init(&parent_private_key);
    bnz_init(&parent_chain_code);
    bnz_init(&parent_public_key_compressed);
    bnz_init(&child_private_key);
    bnz_init(&child_chain_code);
    bnz_init(&child_public_key_compressed);
    bnz_init(&p2wpkh);

    // m/84'
    bnz_set_bnz(&parent_private_key, master_private_key);
    bnz_set_bnz(&parent_chain_code, master_chain_code);
    get_child_hardened(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, 84);

    // m/84'/0'
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_child_hardened(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, 0);

    // m/84'/0'/0'
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_child_hardened(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, 0);

    // m/84'/0'/0'/0
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_public_key_compressed(secp256k1, &parent_public_key_compressed, &parent_private_key);
    get_child_normal(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, &parent_public_key_compressed, 0);

    // m/84'/0'/0'/0/0 to m/84'/0'/0'/0/19
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_public_key_compressed(secp256k1, &parent_public_key_compressed, &parent_private_key);
    for (i = 0; i < 20; i++) {
        get_child_normal(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, &parent_public_key_compressed, i);
        get_public_key_compressed(secp256k1, &child_public_key_compressed, &child_private_key);
        get_p2wpkh_address(&p2wpkh, &child_public_key_compressed);
        printf("m/84'/0'/0'/0/%d: ", i);
        print_p2wpkh_address(&p2wpkh, "");
    }
    printf("\n");

    bnz_free(&parent_private_key);
    bnz_free(&parent_chain_code);
    bnz_free(&parent_public_key_compressed);
    bnz_free(&child_private_key);
    bnz_free(&child_chain_code);
    bnz_free(&p2wpkh);
}

/* BITCOIN ECDSA FUNCTIONS */

void secp256k1_ecdsa_get_random_nonce(const SECP256K1, bnz_t *);
void secp256k1_ecdsa_get_RFC6979_nonce(const SECP256K1, const bnz_t *, const bnz_t *, bnz_t *);
void secp256k1_ecdsa_get_signature_from_r_s(const bnz_t *, const bnz_t *, bnz_t *);
void secp256k1_ecdsa_get_r_s_from_signature(const bnz_t *, bnz_t *, bnz_t *);
void secp256k1_ecdsa_sign(const SECP256K1, const bnz_t *, const bnz_t *, bnz_t *, bnz_t *, uint32_t);
bool secp256k1_ecdsa_verify_from_signature(const SECP256K1, const bnz_t *, const bnz_t *, const bnz_t *);
bool secp256k1_ecdsa_verify_from_r_s(const SECP256K1, const bnz_t *, const bnz_t *, const bnz_t *, const bnz_t *);

void secp256k1_ecdsa_get_random_nonce(SECP256K1 secp256k1, bnz_t *nonce)
{
    do {
        get_256_bit_rnd(nonce); // ensure that nonce is in the range 0 < k < Secp256k1.n
    } while (secp256k1_valid_multiplier(secp256k1, nonce) == false);
}

void secp256k1_ecdsa_get_RFC6979_nonce(const SECP256K1 secp256k1, const bnz_t *private_key, const bnz_t *hash, bnz_t *nonce) // RFC6979
{
    const char *v_str = "0101010101010101010101010101010101010101010101010101010101010101"; // v = 0x1 x 32
    uint8_t mac[32];
    int range_flag;

    bnz_t k, v, key, message, private_key_tmp;
    bnz_init(&k);
    bnz_init(&v);
    bnz_init(&key);
    bnz_init(&message);
    bnz_init(&private_key_tmp);

    bnz_set_bnz(&private_key_tmp, private_key); // mutable copy of private_key to permit resizing to 32 bytes
    bnz_resize(&private_key_tmp, 32, true); // private_key_tmp resized to 32 bytes

    // (a) hash = SHA256(m)

    // (b) V = 0x1 x 32
    bnz_set_str(&v, v_str, 16); // v = 0x1 x 32
    // no need to convert v to big endian order because is is an array of 32 x 0x1 bytes

    // (c) K = 0x0 x 32
    bnz_set_i32(&k, 0); // k = 0x0 x 32

    // (d) K = HMAC_K(V || 0x00 || private_key || hash)
    bnz_set_bnz(&key, &k); // key = k
    // no need to convert key to big endian order because is is an array of 32 x 0x0 bytes
    bnz_resize(&key, 32, true); // ensure key size is 32 bytes

    bnz_set_bnz(&message, &v); // message = v, message will be assembled in little endian order
    bnz_concatenate_ui8(&message, &message, 0, 1); // message = v || 0x0
    bnz_concatenate_bnz(&message, &message, &private_key_tmp, 1); // message = v || 0x0 || private_key_tmp
    bnz_concatenate_bnz(&message, &message, hash, 1); // message = v || 0x0 || private_key_tmp || hash
    bnz_reverse_digits(&message); // convert message to big endian order

    hmac_sha256(key.digits, key.size, message.digits, message.size, mac, 32); // mac = hmac_sha256(key, message)

    bnz_resize(&k, 32, false); // prepare k to receive 32 bytes of mac
    memcpy(k.digits, mac, 32); // k = mac
    bnz_reverse_digits(&k); // convert k to standard little endian order

    // (e) V = HMAC_K(V)
    bnz_set_bnz(&key, &k); // key = k
    bnz_reverse_digits(&key); // convert key to big endian order

    bnz_set_bnz(&message, &v); // message = v
    bnz_reverse_digits(&message); // convert message to big endian order

    hmac_sha256(key.digits, key.size, message.digits, message.size, mac, 32); // mac = hmac_sha256(key, message)

    bnz_resize(&v, 32, false); // prepare v to receive 32 bytes of mac
    memcpy(v.digits, mac, 32); // v = mac
    bnz_reverse_digits(&v); // convert v to standard little endian order

    // (f) K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    bnz_set_bnz(&key, &k); // key = k
    bnz_reverse_digits(&key); // convert key to big endian order
    bnz_resize(&key, 32, true); // ensure that key is 32 bytes

    bnz_set_bnz(&message, &v); // message = v
    bnz_concatenate_ui8(&message, &message, 1, 1); // message = v || 0x1 
    bnz_concatenate_bnz(&message, &message, &private_key_tmp, 1); // message = v || 0x1 || private_key_tmp
    bnz_concatenate_bnz(&message, &message, hash, 1); // message = v || 0x1 || private_key_tmp || hash
    bnz_reverse_digits(&message); // convert message to big endian order

    hmac_sha256(key.digits, key.size, message.digits, message.size, mac, 32); // mac = hmac_sha256(key, message)

    bnz_resize(&k, 32, false); // prepare k to receive 32 bytes of mac
    memcpy(k.digits, mac, 32); // k = mac
    bnz_reverse_digits(&k); // convert k to standard little endian order

    // (g) V = HMAC_K(V)
    bnz_set_bnz(&key, &k); // key = k
    bnz_reverse_digits(&key); // convert key to big endian order

    bnz_set_bnz(&message, &v); // message = v
    bnz_reverse_digits(&message); // convert message to big endian order

    hmac_sha256(key.digits, key.size, message.digits, message.size, mac, 32); // mac = hmac_sha256(key, message)

    bnz_resize(&v, 32, false); // prepare v to receive 32 bytes of mac
    memcpy(v.digits, mac, 32); // v = mac
    bnz_reverse_digits(&v); // convert v to standard little endian order

    // (h) final loop to confirm nonce is at least 32 bytes and lies in the range 1 <= nonce <= secp256k1.n
    do {
        // 1. set nonce to zero length bnz_t
        bnz_init(nonce);

        // 2. V = HMAC_K(V), nonce = nonce || V until nonce.size >= 32
        while (nonce->size < 32) {
            bnz_set_bnz(&key, &k); // key = k
            bnz_reverse_digits(&key); // convert key to big endian order

            bnz_set_bnz(&message, &v); // message = v
            bnz_reverse_digits(&message); // convert message to big endian order

            hmac_sha256(key.digits, key.size, message.digits, message.size, mac, 32); // mac = hmac_sha256(key, message)

            bnz_resize(&v, 32, false); // prepare v to receive 32 bytes of mac
            memcpy(v.digits, mac, 32); // v = mac
            bnz_reverse_digits(&v); // convert v to standard little endian order

            bnz_concatenate_bnz(nonce, nonce, &v, 1); // nonce = nonce || v
        }

        // 3. ensure nonce is in the range 1 to Secp256k1.n
        range_flag = 0;

        if (bnz_cmp_i32(nonce, 1) == -1 || bnz_cmp_bnz(nonce, &secp256k1.n) == 1) {

            // K = HMAC_K(V || 0x00)
            bnz_set_bnz(&key, &k); // key = k

            bnz_set_bnz(&message, &v); // message = v

            bnz_concatenate_ui8(&message, &message, 0, 1); // message = message || 0x0
            bnz_concatenate_bnz(&message, &message, &private_key_tmp, 1); // message = message || 0x0 || private_key_tmp
            bnz_concatenate_bnz(&message, &message, hash, 1); // message = message || 0x0 || private_key_tmp || hash
            bnz_reverse_digits(&message); // convert message to big endian order

            hmac_sha256(key.digits, key.size, message.digits, message.size, mac, 32); // mac = hmac_sha256(key, message)

            bnz_resize(&k, 32, false); // prepare k to receive 32 bytes of mac
            memcpy(k.digits, mac, 32); // k = mac
            bnz_reverse_digits(&k); // convert k to standard little endian order

            // V = HMAC_K(V)
            bnz_set_bnz(&key, &k); // key = k

            bnz_set_bnz(&message, &v); // message = v

            hmac_sha256(key.digits, key.size, message.digits, message.size, mac, 32); // mac = hmac_sha256(key, message)

            bnz_resize(&v, 32, false); // prepare v to receive max
            memcpy(v.digits, mac, 32); // v = mac
            bnz_reverse_digits(&v); // convert to standard little endian order 
        } else {
            range_flag = 1; // if 1 <= nonce <= secp256k1.n, set range_flag 
        }
    } while (range_flag != 1);

    bnz_free(&k);
    bnz_free(&v);
    bnz_free(&key);
    bnz_free(&message);
    bnz_free(&private_key_tmp);
}

void secp256k1_ecdsa_get_signature_from_r_s(const bnz_t *r, const bnz_t *s, bnz_t *signature) // 0x30 [len(signature)] 0x02 [len(r)] [r] 0x02 [len(s)] [s]
{
    uint8_t len;
    bnz_t rr, ss;

    bnz_init(&rr);
    bnz_init(&ss);

    bnz_set_bnz(&rr, r); // mutable copies of r and s
    bnz_set_bnz(&ss, s);

    if (rr.digits[rr.size - 1] > 128) bnz_concatenate_ui8(&rr, &rr, 0, 0); // if msb of r > 128, concatenate 0x0 at msb end
    if (ss.digits[ss.size - 1] > 128) bnz_concatenate_ui8(&ss, &ss, 0, 0); // if msb of s > 128, concatenate 0x0 at msb end

    len = rr.size + ss.size + 6; // len = total length of signature

    bnz_set_ui32(signature, 48); // signature = 0x30
    bnz_concatenate_ui8(signature, signature, len, 1); // concatente total length

    bnz_concatenate_ui8(signature, signature, 2, 1); // concatenate 0x02
    bnz_concatenate_ui8(signature, signature, rr.size, 1); // concatenate len(rr)
    bnz_concatenate_bnz(signature, signature, &rr, 1); // concatenate rr

    bnz_concatenate_ui8(signature, signature, 2, 1); // concatenate 0x02
    bnz_concatenate_ui8(signature, signature, ss.size, 1); // concatenate len(ss)
    bnz_concatenate_bnz(signature, signature, &ss, 1); // concatenate ss

    bnz_free(&rr); // free resources
    bnz_free(&ss);
}

void secp256k1_ecdsa_get_r_s_from_signature(const bnz_t *signature, bnz_t *r, bnz_t *s)
{
    bnz_t tmp;
    bnz_init(&tmp);

    bnz_set_bnz(&tmp, signature); // tmp = local mutable copy of signature, little endian order

    bnz_reverse_digits(&tmp); // reverse tmp.digits, big endian order

    bnz_resize(r, tmp.digits[3], false); // tmp.digits[3] = len(r) 
    memcpy(r->digits, tmp.digits + 4, tmp.digits[3]); // copy len(r) bytes into r, offset 4
    bnz_reverse_digits(r); // convert r.digits to standard little endian order
    bnz_trim(r); // delete any leading zeros from the msb end

    bnz_resize(s, tmp.digits[tmp.digits[3] + 5], false); // tmp.digits[len(r) + 5] = len(s)
    memcpy(s->digits, tmp.digits + tmp.digits[3] + 6, tmp.digits[tmp.digits[3] + 5]); // copy len(s) bytes into s, offset len(r) + 6
    bnz_reverse_digits(s); // convert s.digits to standard little endian order
    bnz_trim(s); // delete any leading zeros from the msb end

    bnz_free(&tmp); // free resources
}

void secp256k1_ecdsa_sign(const SECP256K1 secp256k1, const bnz_t *private_key, const bnz_t *hash, bnz_t *r, bnz_t *s, uint32_t nonce_type) // r = x coordinate of (nonce * Secp256k1.G), s = (hash + (r * private_key)) / nonce
{
    const char *floor_half_n_str = "57896044618658097711785492504343953926418782139537452191302581570759080747168"; // floor(secp256k1.n / 2)
    bnz_t nonce, inv_nonce, floor_half_n;
    APT tmp; // temporary APT

    bnz_init(&nonce); // random nonce ("number used once")
    bnz_init(&inv_nonce); // modular multiplicative inverse of nonce
    bnz_init(&floor_half_n); // floor(secp256k1.n / 2), to determine whether s is "high" or "low"

    bnz_init(&tmp.x);
    bnz_init(&tmp.y);

    bnz_set_str(&floor_half_n, floor_half_n_str, 10); // floor(secp256k1.n / 2)

    if (nonce_type == 0) {
        secp256k1_ecdsa_get_RFC6979_nonce(secp256k1, private_key, hash, &nonce); // RFC6979 deterministic nonce
    } else {
        secp256k1_ecdsa_get_random_nonce(secp256k1, &nonce); // random nonce
    }

    bnz_modular_multiplicative_inverse(&inv_nonce, &nonce, &secp256k1.n); // set value of inv_nonce to the modular multiplicative inverse of nonce, modulo secp256k1.n the curve order
    secp256k1_jacobian_scalar_multiplication(secp256k1, &nonce, &tmp); // tmp = nonce * secp256k1.G (generator point)

    bnz_set_bnz(r, &tmp.x); // r = x coordinate of tmp
    bnz_multiply_bnz(s, private_key, r); // s = private_key * r

    bnz_mod_bnz(s, s, &secp256k1.n); // s = s mod secp256k1.n
    bnz_add_bnz(s, s, hash); // s = s + hash
    bnz_mod_bnz(s, s, &secp256k1.n); // s = s mod secp256k1.n
    bnz_multiply_bnz(s, s, &inv_nonce); // s = s * inv_nonce
    bnz_mod_bnz(s, s, &secp256k1.n); // s = s mod secp256k1.n
    if (bnz_cmp_bnz(s, &floor_half_n) == 1) bnz_subtract_bnz(s, &secp256k1.n, s); // if s > floor(secp256k1.n / 2) ("high s") negate s i.e. s = secp256k1.n - s to ensure "low s"

    bnz_free(&nonce); // free resources
    bnz_free(&inv_nonce);
    bnz_free(&floor_half_n);
    bnz_free(&tmp.x);
    bnz_free(&tmp.y);
}

bool secp256k1_ecdsa_verify_from_signature(const SECP256K1 secp256k1, const bnz_t *public_key_compressed, const bnz_t *hash, const bnz_t *signature)
{
    bool verified;

    bnz_t r, s;

    bnz_init(&r); // variable to hold r extracted from DER format ECDSA signature
    bnz_init(&s); // variable to hold s extracted from DER format ECDSA signature

    secp256k1_ecdsa_get_r_s_from_signature(signature, &r, &s); // extract r and s from DER format ECDSA signature
    verified = secp256k1_ecdsa_verify_from_r_s(secp256k1, public_key_compressed, hash, &r, &s); // verify using r and s

    bnz_free(&r);
    bnz_free(&s);

    return verified;
}

bool secp256k1_ecdsa_verify_from_r_s(const SECP256K1 secp256k1, const bnz_t *public_key_compressed, const bnz_t *hash, const bnz_t *r, const bnz_t *s)
{
    bool verified;
    
    bnz_t inv_s, m1, m2;
    APT public_key_pt, tmp1, tmp2, verification_pt;

    bnz_init(&inv_s);
    bnz_init(&m1);
    bnz_init(&m2);

    bnz_init(&public_key_pt.x);
    bnz_init(&public_key_pt.y);
    bnz_init(&tmp1.x);
    bnz_init(&tmp1.y);
    bnz_init(&tmp2.x);
    bnz_init(&tmp2.y);
    bnz_init(&verification_pt.x);
    bnz_init(&verification_pt.y);

    get_public_key_xy(secp256k1, &public_key_pt, public_key_compressed); // extract xy coordinates of original public key Secp256k1 point from compressed public key

    bnz_modular_multiplicative_inverse(&inv_s, s, &secp256k1.n); // set value of inv_s to the modular multiplicative inverse of s, modulo secp256k1.n the curve order

    bnz_multiply_bnz(&m1, &inv_s, hash); // m1 = inv_s * hash
    bnz_mod_bnz(&m1, &m1, &secp256k1.n); // m1 = m1 mod secp256k1.n
    secp256k1_jacobian_scalar_multiplication(secp256k1, &m1, &tmp1); // tmp1 = m1 * secp256k1.G mod secp256k1.p

    bnz_multiply_bnz(&m2, &inv_s, r); // m2 = inv_s * r
    bnz_mod_bnz(&m2, &m2, &secp256k1.n); // m2 = m2 mod secp256k1.n
    secp256k1_scalar_multiplication(secp256k1, &public_key_pt, &m2, &tmp2); // tmp2 = m2 * public key point mod secp256k1.p

    secp256k1_point_addition(secp256k1, &tmp1, &tmp2, &verification_pt); // verification_pt = tmp1 + tmp2 mod secp256k1.p

    bnz_mod_bnz(&verification_pt.x, &verification_pt.x, &secp256k1.n);// verification_pt.x = verification_pt.x mod secp256k1.n

    if (bnz_cmp_bnz(&verification_pt.x, r) == 0) { // compare verfication_pt.x and r
        verified = true; // if verification_pt.x and r are equal, verification has succeded, set value of verfied to true
    } else {
        verified = false; // if verification_pt.x and r are not equal, verification has failed, set value of verfied to false
    }

    bnz_free(&public_key_pt.x); // free resources
    bnz_free(&public_key_pt.y);
    bnz_free(&tmp1.x);
    bnz_free(&tmp1.y);
    bnz_free(&tmp2.x);
    bnz_free(&tmp2.y);
    bnz_free(&verification_pt.x);
    bnz_free(&verification_pt.y);

    return verified; // return verified
}

/* MENU FUNCTIONS */

uint32_t get_num_input(uint32_t, uint32_t, uint32_t);
void get_str_input(char[], int);
size_t get_file_size(FILE *);
char *get_file_contents(const char *);
void get_file_hash(const char *, uint32_t);
void menu_1_master_keys(const char *);
void menu_2_child_keys(const char *);
void menu_2_1_normal_child(const char *);
void menu_2_2_hardened_child(const char *);
void menu_2_3_public_child(const char *);
void menu_2_4_hdk_intermediate_values(const char *);
void menu_3_base_converter(const char *);
void menu_4_functions(const char *);
void menu_4_1_validate_mnemonic_phrase_checksum(const char *);
void menu_4_2_private_and_public_key_functions(const char *);
void menu_4_2_1_private_key_to_WIF(const char *);
void menu_4_2_2_WIF_to_private_key(const char *);
void menu_4_2_3_public_key_to_address(const char *);
void menu_4_3_secp256k1_functions(const char *);
void menu_4_3_1_secp256k1_x_coordinate_validity(const char *);
void menu_4_3_2_secp256k1_point_addition(const char *);
void menu_4_3_3_secp256k1_point_doubling(const char *);
void menu_4_3_4_secp256k1_scalar_multiplication(const char *);
void menu_4_4_ecdsa_functions(const char *);
void menu_4_4_1_ecdsa_sign(const char *);
void menu_4_4_2_ecdsa_verify_signature(const char *);
void menu_4_4_3_ecdsa_verify_r_s(const char *);
void menu_5_file_hash_functions(const char *);

uint32_t get_num_input(uint32_t max_len, uint32_t min, uint32_t max) // get base 10 number between min and max from stdin
{
    char str[max_len + 1];
    int i = 0, ch;
    uint32_t res;
    while ((ch = getchar()) != '\n' && ch != EOF) {
        if (i < max_len && isdigit(ch)) {
            str[i++] = ch;
        }
    }
    str[i] = 0;
    res = strtoul(str, NULL, 10);
    if (res < min || res > max) res = min;
    return res;
}

void get_str_input(char str[], int max_len) // get string from stdin with strlen <= max_len
{
    int i = 0, ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {
        if (ch >= 32 && ch <= 126 && i < max_len) {
            str[i++] = ch;
        }
    }
    str[i] = 0;
}

size_t get_file_size(FILE *file)
{
    size_t file_size;
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return file_size;
}

char *get_file_contents(const char *file_path)
{
    char *file_contents = NULL;
    size_t file_size, bytes_read;
    FILE *file = NULL;

    file = fopen(file_path, "rb");

    if (!file) {
        printf("Could not open file: %s\n\n", file_path);
        return NULL;
    }

    file_size = get_file_size(file);

    file_contents = malloc(file_size + 1);

    if (!file_contents) {
        fclose(file);
        printf("Could not allocate memory for file contents: %s.\n\n", file_path);
        return NULL;
    }

    memset(file_contents, 0, file_size + 1);
    bytes_read = fread(file_contents, 1, file_size, file);
    fclose(file);

    if (bytes_read != file_size) {
        free(file_contents);
        printf("Could not read entire file: %s.\n\n", file_path);
        return NULL;
    }

    return file_contents;
}

void get_file_hash(const char *version, uint32_t hash_type)
{
    char file_path[256] = {0}, *file_contents = NULL;
    uint32_t file_size;
    FILE *f = NULL;
    bnz_t h;

    bnz_init(&h);

    system("cls");
    printf("%s\n\n", version);

    printf("File path: ");
    get_str_input(file_path, 256);

    file_contents = get_file_contents(file_path);

    if (!file_contents) {
        printf("Press any key to continue...");
        getchar();
        return;
    }

    system("cls");
    printf("%s\n\n", version);

    printf("File path: %s\n\n", file_path);

    switch(hash_type) {
        case 1:
            get_ripemd160(&h, (const uint8_t *)file_contents);
            bnz_print(&h, 16, "RIPEMD160: ");
            break;
        case 2:
            get_sha256(&h, (const uint8_t *)file_contents);
            bnz_print(&h, 16, "SHA256: ");
            break;
        case 3:
            get_sha512(&h, (const uint8_t *)file_contents);
            bnz_print(&h, 16, "SHA512: ");
            break;
        default:
            return;
    }

    free(file_contents);

    printf("\n");

    printf("Press any key to continue...");

    getchar();
}

void menu_1_master_keys(const char *version) // input 256 bits of entropy and generate master private key, master chain code, master public key, and corresponding p2pkh and p2wpkh hdk addresses
{
    uint32_t i, wd_ids[24];
    char entropy_str[257], base = 16, passphrase_str[257], *mnemonic = NULL;
    bnz_t entropy, master_private_key, master_chain_code, master_public_key, master_public_key_compressed, seed;

    SECP256K1 secp256k1;

    bnz_init(&entropy);
    bnz_init(&master_private_key);
    bnz_init(&master_chain_code);
    bnz_init(&master_public_key);
    bnz_init(&master_public_key_compressed);
    bnz_init(&seed);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Entropy (press 'Enter' for random): ");
    get_str_input(entropy_str, 256);

    system("cls");
    printf("%s\n\n", version);
    printf("Entropy: ");

    if (isalnum(entropy_str[0])) {
        printf("%s\n", entropy_str);
        printf("Base (2 - 64): ");
        base = get_num_input(2, 0, 64);
        if (base < 2) base = 16;
        bnz_set_str(&entropy, (const char *)entropy_str, base);
    } else {
        get_256_bit_rnd(&entropy);
    }

    system("cls");
    printf("%s\n\n", version); 
    bnz_print(&entropy, 16, "Entropy: ");
    if (base == 16) {
        printf("Base: 16\n");
    } else {
        printf("Base: 16 (converted from base %d)\n", base);
    }

    printf("Passphrase (optional): ");
    get_str_input(passphrase_str, 256);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&entropy, 16, "ENTROPY: ");
    printf("BASE: 16\n\n");

    entropy_checksum(&entropy);

    get_bip39_word_ids_bnz(&entropy, wd_ids);

    printf("CHECKSUM: 0x%02x\n\n", entropy.digits[0]);

    printf("BIP39 IDs: %d", wd_ids[0]);
    for (i = 1; i < 24; i++) {
        printf(", %d", wd_ids[i]);
    }
    printf("\n\n");

    mnemonic = get_mnemonic_phrase(wd_ids);
    printf("MNEMONIC PHRASE: %s\n\n", mnemonic);

    if (isalnum(passphrase_str[0])) {
        printf("PASSPHRASE: %s\n\n", passphrase_str);
    }

    get_seed_from_mnemonic_phrase(&seed, mnemonic, passphrase_str);
    bnz_print(&seed, 16, "SEED: ");
    printf("\n");

    get_master_keys(&master_private_key, &master_chain_code, &seed);

    if (secp256k1_valid_multiplier(secp256k1, &master_private_key) == false) { // ensure that master_private_key is in the range 0 < k < Secp256k1.n
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&master_private_key, 16, "Master private key: ");
        printf("\n");
        printf("This private key is not in the valid range 0 < k < Secp256k1.\n\n");
        printf("It is not possible to generate a public key from this private key.\n\n");
        printf("Press any key to rerun the command with a different private key value.\n");
        getchar();

        bnz_free(&entropy);
        bnz_free(&master_private_key);
        bnz_free(&master_chain_code);
        bnz_free(&master_public_key);
        bnz_free(&master_public_key_compressed);
        bnz_free(&seed);

        secp256k1_free(secp256k1);

        menu_1_master_keys(version);
    }
    
    bnz_print(&master_private_key, 16, "MASTER PRIVATE KEY: ");
    bnz_print(&master_chain_code, 16, "MASTER CHAIN CODE: ");

    printf("\nHDK ADDRESSES:\n");
    
    get_wallet_p2pkh_addresses(secp256k1, &master_private_key, &master_chain_code);
    get_wallet_p2sh_p2wpkh_addresses(secp256k1, &master_private_key, &master_chain_code);
    get_wallet_p2wpkh_addresses(secp256k1, &master_private_key, &master_chain_code);

    bnz_free(&entropy);
    bnz_free(&master_private_key);
    bnz_free(&master_chain_code);
    bnz_free(&master_public_key);
    bnz_free(&master_public_key_compressed);
    bnz_free(&seed);

    printf("press any key to continue...");

    getchar();
}

void menu_2_child_keys(const char *version)
{
    int menu;
    system("cls");
    printf("%s\n\n", version);
    printf("1. Normal child\n");
    printf("2. Hardened child\n");
    printf("3. Child public key\n");
    printf("4. HDK intermediate values\n");
    printf("\n");
    menu = get_num_input(1, 0, 4);
    switch (menu) {
        case 1:
            menu_2_1_normal_child(version);
            break;
        case 2:
            menu_2_2_hardened_child(version);
            break;
        case 3:
            menu_2_3_public_child(version);
            break;
        case 4:
            menu_2_4_hdk_intermediate_values(version);
            break;
        default:
            break;
    }
}

void menu_2_1_normal_child(const char *version)
{
    uint8_t parent_private_key_str[67], parent_chain_code_str[67], depth_num;
    uint32_t index_num, p2pkh_leading_zeros;
    bnz_t tmp, index, entropy, parent_private_key, parent_chain_code, parent_public_key_compressed, child_private_key, child_chain_code, child_public_key_compressed, p2pkh, p2sh_p2wpkh, p2wpkh;
    APT parent_public_key_pt, child_public_key_pt;
    SECP256K1 secp256k1;

    secp256k1 = secp256k1_init();

    bnz_init(&tmp);
    bnz_init(&index);
    bnz_init(&entropy);
    bnz_init(&parent_private_key);
    bnz_init(&parent_chain_code);
    bnz_init(&parent_public_key_compressed);
    bnz_init(&child_private_key);
    bnz_init(&child_chain_code);
    bnz_init(&child_public_key_compressed);
    bnz_init(&p2pkh);
    bnz_init(&p2sh_p2wpkh);
    bnz_init(&p2wpkh);

    bnz_init(&parent_public_key_pt.x);
    bnz_init(&parent_public_key_pt.y);
    bnz_init(&child_public_key_pt.x);
    bnz_init(&child_public_key_pt.y);

    system("cls");
    printf("%s\n\n", version);

    printf("Parent private key (press 'Enter' for random): ");
    get_str_input(parent_private_key_str, 66);

    if (isalnum(parent_private_key_str[0])) {
        printf("%s\n", parent_private_key_str);
        bnz_set_str(&parent_private_key, (const char *)parent_private_key_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        printf("Parent chain code: ");
        get_str_input(parent_chain_code_str, 66);
        bnz_set_str(&parent_chain_code, (const char *)parent_chain_code_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    } else {
        get_random_master_keys(&entropy, &parent_private_key, &parent_chain_code);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&entropy, 16, "Entropy: ");
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    }

    if (secp256k1_valid_multiplier(secp256k1, &parent_private_key) == false) { // ensure that parent_private_key is in the range 0 < k < Secp256k1.n
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        printf("\n");
        printf("This private key is not in the valid range 0 < k < Secp256k1.\n\n");
        printf("It is not possible to generate a public key from this private key.\n\n");
        printf("Press any key to rerun the command with a different private key value.\n");
        getchar();

        bnz_free(&tmp);
        bnz_free(&index);
        bnz_free(&entropy);
        bnz_free(&parent_private_key);
        bnz_free(&parent_chain_code);
        bnz_free(&parent_public_key_compressed);
        bnz_free(&child_private_key);
        bnz_free(&child_chain_code);
        bnz_free(&child_public_key_compressed);
        bnz_free(&p2pkh);
        bnz_free(&p2sh_p2wpkh);
        bnz_free(&p2wpkh);

        bnz_free(&parent_public_key_pt.x);
        bnz_free(&parent_public_key_pt.y);
        bnz_free(&child_public_key_pt.x);
        bnz_free(&child_public_key_pt.y);

        secp256k1_free(secp256k1);

        menu_2_1_normal_child(version);
    }

    printf("\n");
    printf("Depth (1 to 255): ");
    depth_num = get_num_input(3, 1, 255);

    system("cls");
    printf("%s\n\n", version);
    if (bnz_is_zero(&entropy) == false) bnz_print(&entropy, 16, "Entropy: ");
    bnz_print(&parent_private_key, 16, "Parent private key: ");
    bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    printf("\n");
    printf("Depth: %u\n", depth_num);
    printf("Index (0 to 2147483647): ");
    index_num = get_num_input(11, 0, 2147483647);

    get_public_key(secp256k1, &parent_public_key_pt, &parent_public_key_compressed, &parent_private_key);

    system("cls");
    printf("%s\n\n", version);
    if (bnz_is_zero(&entropy) == false) bnz_print(&entropy, 16, "ENTROPY: ");
    bnz_print(&parent_private_key, 16, "PARENT PRIVATE KEY: ");
    bnz_print(&parent_chain_code, 16, "PARENT CHAIN CODE: ");
    bnz_print(&parent_public_key_compressed, 16, "PARENT PUBLIC KEY COMPRESSED: ");
    bnz_print(&parent_public_key_pt.x, 16, " x: ");
    bnz_print(&parent_public_key_pt.y, 16, " y: ");
    printf("\n");
    printf("DEPTH: %u\n", depth_num);
    printf("INDEX: %u\n", index_num);
    printf("\n");

    get_child_normal(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, &parent_public_key_compressed, index_num);

    bnz_print(&child_private_key, 16, "CHILD PRIVATE KEY: ");
    bnz_print(&child_chain_code, 16, "CHILD CHAIN CODE: ");
    printf("\n");

    get_public_key(secp256k1, &child_public_key_pt, &child_public_key_compressed, &child_private_key); // generate compressed public key from private key
    get_p2pkh_address(&p2pkh, &child_public_key_compressed, &p2pkh_leading_zeros); // serialise p2pkh address
    get_p2sh_p2wpkh_address(&p2sh_p2wpkh, &child_public_key_compressed); // serialise p2sh_p2wpkh address
    get_p2wpkh_address(&p2wpkh, &parent_public_key_compressed); // serialise p2wpkh address

    bnz_print(&child_public_key_compressed, 16, "CHILD PUBLIC KEY COMPRESSED: ");
    bnz_print(&child_public_key_pt.x, 16, " x: ");
    bnz_print(&child_public_key_pt.y, 16, " y: ");
    print_p2pkh_address(&p2pkh, "CHILD P2PKH ADDRESS: ", p2pkh_leading_zeros);
    bnz_print(&p2sh_p2wpkh, 58, "CHILD P2SH-P2WPKH ADDRESS: ");
    print_p2wpkh_address(&p2wpkh, "CHILD P2WPKH ADDRESS: ");
    printf("\n");

    bnz_free(&tmp);
    bnz_free(&index);
    bnz_free(&entropy);
    bnz_free(&parent_private_key);
    bnz_free(&parent_chain_code);
    bnz_free(&parent_public_key_compressed);
    bnz_free(&child_private_key);
    bnz_free(&child_chain_code);
    bnz_free(&child_public_key_compressed);
    bnz_free(&p2pkh);
    bnz_free(&p2sh_p2wpkh);
    bnz_free(&p2wpkh);

    bnz_free(&parent_public_key_pt.x);
    bnz_free(&parent_public_key_pt.y);
    bnz_free(&child_public_key_pt.x);
    bnz_free(&child_public_key_pt.y);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_2_2_hardened_child(const char *version)
{
    uint8_t parent_private_key_str[67], parent_chain_code_str[67], depth_num;
    uint32_t index_num, p2pkh_leading_zeros;
    bnz_t tmp, index, entropy, parent_private_key, parent_chain_code, parent_public_key_compressed, child_private_key, child_chain_code, child_public_key_compressed, p2pkh, p2sh_p2wpkh, p2wpkh;
    APT parent_public_key_pt, child_public_key_pt;
    SECP256K1 secp256k1;

    secp256k1 = secp256k1_init();

    bnz_init(&tmp);
    bnz_init(&index);
    bnz_init(&entropy);
    bnz_init(&parent_private_key);
    bnz_init(&parent_chain_code);
    bnz_init(&parent_public_key_compressed);
    bnz_init(&child_private_key);
    bnz_init(&child_chain_code);
    bnz_init(&child_public_key_compressed);
    bnz_init(&p2pkh);
    bnz_init(&p2sh_p2wpkh);
    bnz_init(&p2wpkh);

    bnz_init(&parent_public_key_pt.x);
    bnz_init(&parent_public_key_pt.y);
    bnz_init(&child_public_key_pt.x);
    bnz_init(&child_public_key_pt.y);

    system("cls");
    printf("%s\n\n", version);

    printf("Parent private key (press 'Enter' for random): ");
    get_str_input(parent_private_key_str, 66);

    if (isalnum(parent_private_key_str[0])) {
        printf("%s\n", parent_private_key_str);
        bnz_set_str(&parent_private_key, (const char *)parent_private_key_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        printf("Parent chain code: ");
        get_str_input(parent_chain_code_str, 66);
        bnz_set_str(&parent_chain_code, (const char *)parent_chain_code_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    } else {
        get_random_master_keys(&entropy, &parent_private_key, &parent_chain_code);
        system("cls");
        printf("%s\n\n", version);
        if (bnz_is_zero(&entropy) == false) bnz_print(&entropy, 16, "Entropy: ");
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    }

    if (secp256k1_valid_multiplier(secp256k1, &parent_private_key) == false) { // ensure that parent_private_key is in the range 0 < k < Secp256k1.n
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        printf("\n");
        printf("This private key is not in the valid range 0 < k < Secp256k1.\n\n");
        printf("It is not possible to generate a public key from this private key.\n\n");
        printf("Press any key to rerun the command with a different private key value.\n");

        getchar();

        bnz_free(&tmp);
        bnz_free(&index);
        bnz_free(&entropy);
        bnz_free(&parent_private_key);
        bnz_free(&parent_chain_code);
        bnz_free(&parent_public_key_compressed);
        bnz_free(&child_private_key);
        bnz_free(&child_chain_code);
        bnz_free(&child_public_key_compressed);
        bnz_free(&p2pkh);
        bnz_free(&p2sh_p2wpkh);
        bnz_free(&p2wpkh);
    
        secp256k1_free(secp256k1);

        menu_2_2_hardened_child(version);
    }

    printf("\n");
    printf("Depth (1 to 255): ");
    depth_num = get_num_input(3, 1, 255);

    system("cls");
    printf("%s\n\n", version);
    if (bnz_is_zero(&entropy) == false) bnz_print(&entropy, 16, "Entropy: ");
    bnz_print(&parent_private_key, 16, "Parent private key: ");
    bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    printf("\n");
    printf("Depth: %u\n", depth_num);
    printf("Index (2147483648 to 4294967295): ");
    index_num = get_num_input(10, 0, 4294967295);
    if (index_num < 2147483648) index_num += 2147483648;

    get_public_key(secp256k1, &parent_public_key_pt, &parent_public_key_compressed, &parent_private_key);

    system("cls");
    printf("%s\n\n", version);
    if (bnz_is_zero(&entropy) == false) bnz_print(&entropy, 16, "ENTROPY: ");
    bnz_print(&parent_private_key, 16, "PARENT PRIVATE KEY: ");
    bnz_print(&parent_chain_code, 16, "PARENT CHAIN CODE: ");
    bnz_print(&parent_public_key_compressed, 16, "PARENT PUBLIC KEY COMPRESSED: ");
    bnz_print(&parent_public_key_pt.x, 16, " x: ");
    bnz_print(&parent_public_key_pt.y, 16, " y: ");
    printf("\n");
    printf("DEPTH: %u\n", depth_num);
    printf("INDEX: %u\n", index_num);
    printf("\n");

    get_child_hardened(secp256k1, &child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, index_num);

    bnz_print(&child_private_key, 16, "CHILD PRIVATE KEY: ");
    bnz_print(&child_chain_code, 16, "CHILD CHAIN CODE: ");
    printf("\n");

    get_public_key(secp256k1, &child_public_key_pt, &child_public_key_compressed, &child_private_key); // generate compressed public key from private key
    get_p2pkh_address(&p2pkh, &child_public_key_compressed, &p2pkh_leading_zeros); // serialise p2pkh address
    get_p2sh_p2wpkh_address(&p2sh_p2wpkh, &child_public_key_compressed); // serialise p2sh_p2wpkh address
    get_p2wpkh_address(&p2wpkh, &child_public_key_compressed);

    bnz_print(&child_public_key_compressed, 16, "CHILD PUBLIC KEY COMPRESSED: ");
    bnz_print(&child_public_key_pt.x, 16, " x: ");
    bnz_print(&child_public_key_pt.y, 16, " y: ");
    print_p2pkh_address(&p2pkh, "CHILD P2PKH ADDRESS: ", p2pkh_leading_zeros);
    bnz_print(&p2sh_p2wpkh, 58, "CHILD P2SH-P2WPKH ADDRESS: ");
    print_p2wpkh_address(&p2wpkh, "CHILD P2WPKH ADDRESS: ");
    printf("\n");

    bnz_free(&tmp);
    bnz_free(&index);
    bnz_free(&entropy);
    bnz_free(&parent_private_key);
    bnz_free(&parent_chain_code);
    bnz_free(&parent_public_key_compressed);
    bnz_free(&child_private_key);
    bnz_free(&child_chain_code);
    bnz_free(&child_public_key_compressed);
    bnz_free(&p2pkh);
    bnz_free(&p2sh_p2wpkh);
    bnz_free(&p2wpkh);

    bnz_free(&child_public_key_pt.x);
    bnz_free(&child_public_key_pt.y);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_2_3_public_child(const char *version)
{
    uint8_t parent_public_key_compressed_str[69], parent_chain_code_str[67], mac[65], depth_num;
    uint32_t index_num, p2pkh_leading_zeros;
    bnz_t tmp, index, parent_public_key_compressed, parent_chain_code, child_public_key_compressed, child_chain_code, p2pkh, p2sh_p2wpkh, p2wpkh;
    APT tmp_key, parent_public_key_pt, child_public_key_pt;

    SECP256K1 secp256k1;

    bnz_init(&tmp);
    bnz_init(&index);
    bnz_init(&parent_public_key_compressed);
    bnz_init(&parent_chain_code);
    bnz_init(&child_public_key_compressed);
    bnz_init(&child_chain_code);
    bnz_init(&p2pkh);
    bnz_init(&p2sh_p2wpkh);
    bnz_init(&p2wpkh);

    bnz_init(&tmp_key.x);
    bnz_init(&tmp_key.y);
    bnz_init(&parent_public_key_pt.x);
    bnz_init(&parent_public_key_pt.y);
    bnz_init(&child_public_key_pt.x);
    bnz_init(&child_public_key_pt.y);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Parent public key compressed: ");
    get_str_input(parent_public_key_compressed_str, 68); // optional "0x" + 33 bytes

    if (isalnum(parent_public_key_compressed_str[0])) {
        printf("%s\n", parent_public_key_compressed_str);
        bnz_set_str(&parent_public_key_compressed, (const char *)parent_public_key_compressed_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_public_key_compressed, 16, "Parent public key compressed: ");
        printf("Parent chain code: ");
        get_str_input(parent_chain_code_str, 66); // 32 bytes + optional "0x"
        bnz_set_str(&parent_chain_code, (const char *)parent_chain_code_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_public_key_compressed, 16, "Parent public key compressed: ");
        bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    } else {
        return;
    }

    printf("\n");
    printf("Depth (1 to 255): ");
    depth_num = get_num_input(3, 1, 255);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&parent_public_key_compressed, 16, "Parent public key compressed: ");
    bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    printf("\n");
    printf("Depth: %u\n", depth_num);
    printf("Index (0 to 2147483647): ");
    index_num = get_num_input(10, 0, 2147483647);

    get_public_key_xy(secp256k1, &parent_public_key_pt, &parent_public_key_compressed);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&parent_chain_code, 16, "PARENT CHAIN CODE: ");
    bnz_print(&parent_public_key_compressed, 16, "PARENT PUBLIC KEY COMPRESSED: ");
    bnz_print(&parent_public_key_pt.x, 16, " x: ");
    bnz_print(&parent_public_key_pt.y, 16, " y: ");
    printf("\n");
    printf("DEPTH: %u\n", depth_num);
    printf("INDEX: %u\n", index_num);
    printf("\n");

    bnz_set_i32(&index, index_num); // convert index to bnz_t
    bnz_resize(&index, 4, true); // ensure that index is four bytes
    bnz_resize(&parent_public_key_compressed, 33, true); // ensure that parent_public_key_compressed is 33 bytes
    bnz_resize(&parent_chain_code, 32, true); // ensure that parent_chain_code is 32 bytes

    bnz_concatenate_bnz(&tmp, &parent_public_key_compressed, &index, 1); // tmp = parent_public_key_compressed concatenated with index

    bnz_reverse_digits(&tmp);  // convert tmp.digits to big endian in preparation for hmac_512
    bnz_reverse_digits(&parent_chain_code); // convert parent_chain_code.digits to big endian in preparation for hmac_512

    hmac_sha512(parent_chain_code.digits, parent_chain_code.size, tmp.digits, tmp.size, mac, 64); // generate mac
    bnz_reverse_digits(&parent_chain_code); // convert parent_chain_code.digits back to default little endian

    bnz_resize(&tmp, 32, false); // resize and zero tmp in preparation for receipt of first 32 bytes of mac
    memcpy(tmp.digits, mac, 32); // copy first 32 bytes of mac into tmp.digits
    bnz_reverse_digits(&tmp); // convert tmp.digits back to default little endian

    secp256k1_point_addition(secp256k1, &parent_public_key_pt, &tmp_key, &child_public_key_pt); // child_public_key_pt = (parent_public_key_pt + tmp) mod secp256k1.p

    if (bnz_bit_set(&child_public_key_pt.y, 0) == false) { // even
        bnz_concatenate_ui8(&child_public_key_compressed, &child_public_key_pt.x, 2, 0); // prepend 2
    } else { // odd
        bnz_concatenate_ui8(&child_public_key_compressed, &child_public_key_pt.x, 3, 0); // prepend 3
    }

    bnz_resize(&child_chain_code, 32, 0); // resize and zero child_chain_code in preparation for receipt of last 32 bytes of mac
    memcpy(child_chain_code.digits, mac + 32, 32); // copy first 32 bytes of mac into child_chain_code.digits
    bnz_reverse_digits(&child_chain_code); // convert child_chain_code.digits back to default little endian

    get_p2pkh_address(&p2pkh, &child_public_key_compressed, &p2pkh_leading_zeros); // serialise p2pkh address
    get_p2sh_p2wpkh_address(&p2sh_p2wpkh, &child_public_key_compressed); // serialise p2sh_p2wpkh address
    get_p2wpkh_address(&p2wpkh, &child_public_key_compressed);

    bnz_print(&child_chain_code, 16, "CHILD CHAIN CODE: ");
    bnz_print(&child_public_key_compressed, 16, "CHILD PUBLIC KEY COMPRESSED: ");
    bnz_print(&child_public_key_pt.x, 16, " x: ");
    bnz_print(&child_public_key_pt.y, 16, " y: ");
    print_p2pkh_address(&p2pkh, "CHILD P2PKH ADDRESS: ", p2pkh_leading_zeros);
    bnz_print(&p2sh_p2wpkh, 58, "CHILD P2SH-P2WPKH ADDRESS: ");
    print_p2wpkh_address(&p2wpkh, "CHILD P2WPKH ADDRESS: ");
    printf("\n");

    bnz_free(&tmp);
    bnz_free(&index);
    bnz_free(&parent_public_key_compressed);
    bnz_free(&parent_chain_code);
    bnz_free(&child_public_key_compressed);
    bnz_free(&child_chain_code);
    bnz_free(&p2pkh);
    bnz_free(&p2sh_p2wpkh);
    bnz_free(&p2wpkh);

    bnz_free(&tmp_key.x);
    bnz_free(&tmp_key.y);
    bnz_free(&parent_public_key_pt.x);
    bnz_free(&parent_public_key_pt.y);
    bnz_free(&child_public_key_pt.x);
    bnz_free(&child_public_key_pt.y);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_2_4_hdk_intermediate_values(const char *version)
{
    char hdk_str[32], master_private_key_str[67], master_chain_code_str[67];

    bnz_t entropy, master_private_key, master_chain_code;

    SECP256K1 secp256k1;

    bnz_init(&entropy);
    bnz_init(&master_private_key);
    bnz_init(&master_chain_code);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Master private key (press 'Enter' for random): ");
    get_str_input(master_private_key_str, 66);

    if (isalnum(master_private_key_str[0])) {
        printf("%s\n", master_private_key_str);
        bnz_set_str(&master_private_key, (const char *)master_private_key_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&master_private_key, 16, "Master private key: ");
        printf("Master chain code: ");
        get_str_input(master_chain_code_str, 66);
        bnz_set_str(&master_chain_code, (const char *)master_chain_code_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&master_private_key, 16, "Master private key: ");
        bnz_print(&master_chain_code, 16, "Master chain code: ");
    } else {
        get_random_master_keys(&entropy, &master_private_key, &master_chain_code);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&entropy, 16, "Entropy: ");
        bnz_print(&master_private_key, 16, "Master private key: ");
        bnz_print(&master_chain_code, 16, "Master chain code: ");
    }

    if (secp256k1_valid_multiplier(secp256k1, &master_private_key) == false) { // ensure that master_private_key is in the range 0 < k < Secp256k1.n
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&master_private_key, 16, "Master private key: ");
        printf("\n");
        printf("This private key is not in the valid range 0 < k < Secp256k1.\n\n");
        printf("It is not possible to generate a public key from this private key.\n\n");
        printf("Press any key to rerun the command with a different private key value.\n");

        getchar();

        bnz_free(&entropy);
        bnz_free(&master_private_key);
        bnz_free(&master_chain_code);
    
        secp256k1_free(secp256k1);

        menu_2_4_hdk_intermediate_values(version);
    }

    printf("\n");
    printf("HDK string (e.g. m/44'/0'/0'/0/0): ");
    get_str_input(hdk_str, 31);

    system("cls");
    printf("%s\n\n", version);
    if (bnz_is_zero(&entropy) == false) bnz_print(&entropy, 16, "ENTROPY: ");
    bnz_print(&master_private_key, 16, "MASTER PRIVATE KEY: ");
    bnz_print(&master_chain_code, 16, "MASTER CHAIN CODE: ");
    printf("HDK STRING: %s\n", hdk_str);
    printf("\n");

    get_hdk_intermediate_values(secp256k1, &master_private_key, &master_chain_code, hdk_str);

    bnz_free(&entropy);
    bnz_free(&master_private_key);
    bnz_free(&master_chain_code);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_3_base_converter(const char *version)
{
    char number_str[2049], base = 16;
    bnz_t number;

    bnz_init(&number);

    system("cls");
    printf("%s\n\n", version);

    printf("Number (press 'Enter' for random): ");
    get_str_input(number_str, 2048);

    system("cls");
    printf("%s\n\n", version);

    if (isalnum(number_str[0])) {
        printf("Number: %s\n", number_str);
        printf("Base (2 - 64): ");
        base = get_num_input(3, 2, 64);
        if (base == 0) base = 16;
        bnz_set_str(&number, (const char *)number_str, base);
    } else {
        get_256_bit_rnd(&number);
    }

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&number, base, "Number: ");
    printf("Base: %d\n\n", base);

    bnz_print(&number, -2, "Binary: ");
    printf("\n");

    bnz_print(&number, 8, "Octal: ");
    printf("\n");

    bnz_print(&number, 10, "Decimal: ");
    printf("\n");

    bnz_print(&number, 16, "Hex: ");
    printf("\n");

    bnz_print(&number, 32, "Bech32: ");
    printf("\n");

    bnz_print(&number, 58, "Bitcoin base 58: ");
    printf("\n");

    bnz_print(&number, 256, "Bytes: ");
    printf("\n");

    bnz_print(&number, 2, "Base 2: ");
    bnz_print(&number, 3, "Base 3: ");
    bnz_print(&number, 4, "Base 4: ");
    bnz_print(&number, 5, "Base 5: ");
    bnz_print(&number, 6, "Base 6: ");
    bnz_print(&number, 7, "Base 7: ");
    bnz_print(&number, 8, "Base 8: ");
    bnz_print(&number, 9, "Base 9: ");

    printf("\n");

    bnz_print(&number, 10, "Base 10: ");
    bnz_print(&number, 11, "Base 11: ");
    bnz_print(&number, 12, "Base 12: ");
    bnz_print(&number, 13, "Base 13: ");
    bnz_print(&number, 14, "Base 14: ");
    bnz_print(&number, 15, "Base 15: ");
    bnz_print(&number, -16, "Base 16: ");
    bnz_print(&number, 17, "Base 17: ");
    bnz_print(&number, 18, "Base 18: ");
    bnz_print(&number, 19, "Base 19: ");

    printf("\n");

    bnz_print(&number, 20, "Base 20: ");
    bnz_print(&number, 21, "Base 21: ");
    bnz_print(&number, 22, "Base 22: ");
    bnz_print(&number, 23, "Base 23: ");
    bnz_print(&number, 24, "Base 24: ");
    bnz_print(&number, 25, "Base 25: ");
    bnz_print(&number, 26, "Base 26: ");
    bnz_print(&number, 27, "Base 27: ");
    bnz_print(&number, 28, "Base 28: ");
    bnz_print(&number, 29, "Base 29: ");

    printf("\n");

    bnz_print(&number, 30, "Base 30: ");
    bnz_print(&number, 31, "Base 31: ");
    bnz_print(&number, -32, "Base 32: ");
    bnz_print(&number, 33, "Base 33: ");
    bnz_print(&number, 34, "Base 34: ");
    bnz_print(&number, 35, "Base 35: ");
    bnz_print(&number, 36, "Base 36: ");
    bnz_print(&number, 37, "Base 37: ");
    bnz_print(&number, 38, "Base 38: ");
    bnz_print(&number, 39, "Base 39: ");

    printf("\n");

    bnz_print(&number, 40, "Base 40: ");
    bnz_print(&number, 41, "Base 41: ");
    bnz_print(&number, 42, "Base 42: ");
    bnz_print(&number, 43, "Base 43: ");
    bnz_print(&number, 44, "Base 44: ");
    bnz_print(&number, 45, "Base 45: ");
    bnz_print(&number, 46, "Base 46: ");
    bnz_print(&number, 47, "Base 47: ");
    bnz_print(&number, 48, "Base 48: ");
    bnz_print(&number, 49, "Base 49: ");

    printf("\n");

    bnz_print(&number, 50, "Base 50: ");
    bnz_print(&number, 51, "Base 51: ");
    bnz_print(&number, 52, "Base 52: ");
    bnz_print(&number, 53, "Base 53: ");
    bnz_print(&number, 54, "Base 54: ");
    bnz_print(&number, 55, "Base 55: ");
    bnz_print(&number, 56, "Base 56: ");
    bnz_print(&number, 57, "Base 57: ");
    bnz_print(&number, -58, "Base 58: ");
    bnz_print(&number, 59, "Base 59: ");

    printf("\n");

    bnz_print(&number, 60, "Base 60: ");
    bnz_print(&number, 61, "Base 61: ");
    bnz_print(&number, 62, "Base 62: ");
    bnz_print(&number, 63, "Base 63: ");
    bnz_print(&number, 64, "Base 64: ");

    printf("\n");

    bnz_free(&number);

    printf("press any key to continue...");

    getchar();
}

void menu_4_functions(const char *version)
{
    int menu;
    system("cls");
    printf("%s\n\n", version);
    printf("1. Validate mnemonic phrase checksum\n");
    printf("2. Private and public key functions\n");
    printf("3. Secp256k1 functions\n");
    printf("4. ECDSA functions\n");
    printf("\n");
    menu = get_num_input(1, 0, 4);
    switch (menu) {
        case 1:
            menu_4_1_validate_mnemonic_phrase_checksum(version);
            break;
        case 2:
            menu_4_2_private_and_public_key_functions(version);
            break;
        case 3:
            menu_4_3_secp256k1_functions(version);
            break;
        case 4:
            menu_4_4_ecdsa_functions(version);
            break;
        default:
            break;
    }
}

void menu_4_1_validate_mnemonic_phrase_checksum(const char *version) // check validity of entropy checksum from mnemonic phrase comprising 24 BIP39 words
{
    uint8_t chk;
    char mnemonic_str[257];
    bnz_t entropy, entropy_chk;

    bnz_init(&entropy);
    bnz_init(&entropy_chk);

    system("cls");
    printf("%s\n\n", version);

    printf("Mnemonic phrase (24 BIP39 words): ");
    get_str_input(mnemonic_str, 256);

    system("cls");
    printf("%s\n\n", version);
    printf("Mnemonic phrase: ");

    if (isalnum(mnemonic_str[0])) {
        printf("%s\n", mnemonic_str);
    } else {
        return;
    }

    system("cls");
    printf("%s\n\n", version);
    printf("MNEMONIC PHRASE: ");

    printf("%s\n\n", mnemonic_str);

    get_bip39_word_ids_str(&entropy_chk, &entropy, &chk, mnemonic_str);

    bnz_print(&entropy, 16, "ENTROPY (HEX): ");
    printf("\n");
    bnz_print(&entropy, 2, "ENTROPY (BINARY): ");
    printf("\n");
    if (chk == entropy_chk.digits[0]) {
        printf("CHECKSUM OK: %#02x\n\n", chk);
    } else {
        printf("CHECKSUM ERROR: %#02x SHOULD BE %#02x\n\n", chk, entropy_chk.digits[0]);
    }

    bnz_free(&entropy);
    bnz_free(&entropy_chk);

    printf("press any key to continue...");

    getchar();
}

void menu_4_2_private_and_public_key_functions(const char *version)
{
    int menu;
    system("cls");
    printf("%s\n\n", version);
    printf("1. Private key to WIF / public key / P2PKH / P2SH-P2WPKH / P2WPKH address\n");
    printf("2. WIF to private key / public key / P2PKH / P2SH-P2WPKH / P2WPKH address\n");
    printf("3. Public key to P2PKH, P2SH-P2WPKH and P2WPKH address\n");
    printf("\n");
    menu = get_num_input(1, 0, 3);
    switch (menu) {
        case 1:
            menu_4_2_1_private_key_to_WIF(version);
            break;
        case 2:
            menu_4_2_2_WIF_to_private_key(version);
            break;
        case 3:
            menu_4_2_3_public_key_to_address(version);
            break;
        default:
            break;
    }
}

void menu_4_2_1_private_key_to_WIF(const char *version)
{
    uint8_t private_key_str[67]; // optional "0x" + 32 bytes + null terminus
    uint32_t p2pkh_leading_zeros;
    bnz_t private_key_wif, private_key, entropy, chain_code, public_key_compressed, p2pkh, p2sh_p2wpkh, p2wpkh, fingerprint;
    APT public_key;
    
    SECP256K1 secp256k1;

    bnz_init(&private_key_wif);
    bnz_init(&private_key);
    bnz_init(&entropy);
    bnz_init(&chain_code);
    bnz_init(&public_key_compressed);
    bnz_init(&p2pkh);
    bnz_init(&p2sh_p2wpkh);
    bnz_init(&p2wpkh);
    bnz_init(&public_key.x);
    bnz_init(&public_key.y);
    bnz_init(&fingerprint);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Private key (press 'Enter' for random): ");
    get_str_input(private_key_str, 66);

    if (isalnum(private_key_str[0])) {
        printf("%s\n", private_key_str);
        bnz_set_str(&private_key, (const char *)private_key_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&private_key, 16, "Private key: ");
    } else {
        get_random_master_keys(&entropy, &private_key, &chain_code);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&entropy, 16, "Entropy: ");
        bnz_print(&private_key, 16, "Private key: ");
    }

    printf("\n");

    if (secp256k1_valid_multiplier(secp256k1, &private_key) == false) { // ensure that private_key is valid
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&private_key, 16, "Private key: ");
        printf("\n");
        printf("This private key is not in the valid range 0 < k < Secp256k1.\n\n");
        printf("It is not possible to generate a public key from this private key.\n\n");
        printf("Press any key to rerun the command with a different private key value.\n");

        getchar();

        bnz_free(&private_key_wif);
        bnz_free(&private_key);
        bnz_free(&entropy);
        bnz_free(&chain_code);
        bnz_free(&public_key_compressed);
        bnz_free(&p2pkh);
        bnz_free(&p2sh_p2wpkh);
        bnz_free(&public_key.x);
        bnz_free(&public_key.y);
        bnz_free(&fingerprint);
    
        secp256k1_free(secp256k1);

        menu_4_2_1_private_key_to_WIF(version);
    }

    bnz_set_bnz(&private_key_wif, &private_key); // copy private key to private_key_wif
    bnz_concatenate_ui8(&private_key_wif, &private_key_wif, 0x80, 0); // mainnet version, concatenate 0x80 to msb end (for testnet version concatenate 0xef)
    bnz_concatenate_ui8(&private_key_wif, &private_key_wif, 0x01, 1); // compressed, concatenate 0x01 to lsb end (no concatenatation for uncompressed)

    get_sha256_sha256(&fingerprint, &private_key_wif, 4); // set fingerprint to first four bytes of sha256(sha256(private_key_wif.digits))
    bnz_concatenate_bnz(&private_key_wif, &private_key_wif, &fingerprint, 1); // concatenate fingerprint to lsb end of private_key_wif

    system("cls");
    printf("%s\n\n", version);

    if (bnz_is_zero(&entropy) == false) bnz_print(&entropy, 16, "ENTROPY: ");
    bnz_print(&private_key, 16, "PRIVATE KEY: ");
    bnz_print(&private_key_wif, 16, "PRIVATE KEY WIF (HEX): "); // hex version of WIF
    bnz_print(&private_key_wif, 58, "PRIVATE KEY WIF (BITCOIN BASE 58): "); // Bitcoin Base 58 version of WIF (standard)

    get_public_key(secp256k1, &public_key, &public_key_compressed, &private_key);
    get_p2pkh_address(&p2pkh, &public_key_compressed, &p2pkh_leading_zeros);
    get_p2sh_p2wpkh_address(&p2sh_p2wpkh, &public_key_compressed);
    get_p2wpkh_address(&p2wpkh, &public_key_compressed);

    printf("\n");

    bnz_print(&public_key_compressed, 16, "PUBLIC KEY (COMPRESSED): ");
    print_p2pkh_address(&p2pkh, "P2PKH ADDRESS: ", p2pkh_leading_zeros);
    bnz_print(&p2sh_p2wpkh, 58, "P2SH-P2WPKH ADDRESS: ");
    print_p2wpkh_address(&p2wpkh, "P2WPKH ADDRESS: ");

    printf("\n");

    bnz_free(&private_key_wif);
    bnz_free(&private_key);
    bnz_free(&entropy);
    bnz_free(&chain_code);
    bnz_free(&public_key_compressed);
    bnz_free(&p2pkh);
    bnz_free(&p2sh_p2wpkh);
    bnz_free(&p2wpkh);
    bnz_free(&public_key.x);
    bnz_free(&public_key.y);
    bnz_free(&fingerprint);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_4_2_2_WIF_to_private_key(const char *version)
{
    uint8_t wif_str[53]; // 51 or 52 Bitcoin base 58 characters + null terminus
    uint32_t p2pkh_leading_zeros;
    bnz_t private_key_wif, private_key, public_key_compressed, p2pkh, p2sh_p2wpkh, p2wpkh;

    APT public_key;

    SECP256K1 secp256k1;
    
    bnz_init(&private_key_wif);
    bnz_init(&private_key);
    bnz_init(&public_key_compressed);
    bnz_init(&p2pkh);
    bnz_init(&p2sh_p2wpkh);
    bnz_init(&p2wpkh);
    bnz_init(&public_key.x);
    bnz_init(&public_key.y);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Private key WIF (Bitcoin base 58): ");
    get_str_input(wif_str, 52);

    printf("%s\n", wif_str);
    bnz_set_str(&private_key_wif, (const char *)wif_str, 58);
    system("cls");
    printf("%s\n\n", version);
    bnz_print(&private_key_wif, 58, "Private key WIF (Bitcoin base 58): ");

    printf("\n");

    bnz_set_bnz(&private_key, &private_key_wif); // copy wif to private key
    bnz_resize(&private_key, private_key_wif.size - 1, true); // remove version byte from msb end
    bnz_reverse_digits(&private_key); // reverse private_key.digits to enable 4 checksum bytes to be removed from msb end
    bnz_resize(&private_key, private_key_wif.size - 5, true); // remove 4 checksum bytes from msb end
    bnz_resize(&private_key, 32, true); // resize private_key.digits to 32 bytes to ensure than the compression byte (if present) is deleted
    bnz_reverse_digits(&private_key); // reverse private_key.digits to standard little endian order

    system("cls");
    printf("%s\n\n", version);

    bnz_print(&private_key_wif, 58, "PRIVATE KEY WIF (BITCOIN BASE 58): "); // Bitcoin Base 58 version of WIF (standard)
    bnz_print(&private_key_wif, 16, "PRIVATE KEY WIF (HEX): "); // hex version of WIF
    bnz_print(&private_key, 16, "PRIVATE KEY: "); // hex version of private key

    get_public_key(secp256k1, &public_key, &public_key_compressed, &private_key);
    get_p2pkh_address(&p2pkh, &public_key_compressed, &p2pkh_leading_zeros);
    get_p2sh_p2wpkh_address(&p2sh_p2wpkh, &public_key_compressed);
    get_p2wpkh_address(&p2wpkh, &public_key_compressed);

    printf("\n");

    bnz_print(&public_key_compressed, 16, "PUBLIC KEY (COMPRESSED): ");
    print_p2pkh_address(&p2pkh, "P2PKH ADDRESS: ", p2pkh_leading_zeros);
    bnz_print(&p2sh_p2wpkh, 58, "P2SH-P2WPKH ADDRESS: ");
    print_p2wpkh_address(&p2wpkh, "P2WPKH ADDRESS: ");

    printf("\n");

    bnz_free(&private_key_wif);
    bnz_free(&private_key);
    bnz_free(&public_key_compressed);
    bnz_free(&p2pkh);
    bnz_free(&p2sh_p2wpkh);
    bnz_free(&p2wpkh);
    bnz_free(&public_key.x);
    bnz_free(&public_key.y);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_4_2_3_public_key_to_address(const char *version)
{
    uint8_t public_key_compressed_str[69]; // optional "0x" + 33 bytes + null terminus
    uint32_t p2pkh_leading_zeros;
    bnz_t public_key_compressed, p2pkh, p2sh_p2wpkh, p2wpkh;

    bnz_init(&public_key_compressed);
    bnz_init(&p2pkh);
    bnz_init(&p2sh_p2wpkh);
    bnz_init(&p2wpkh);

    system("cls");
    printf("%s\n\n", version);

    printf("Public key (compressed): ");
    get_str_input(public_key_compressed_str, 68);
    bnz_set_str(&public_key_compressed, (const char *)public_key_compressed_str, 16);

    system("cls");
    printf("%s\n\n", version);

    bnz_print(&public_key_compressed, 16, "PUBLIC KEY (COMPRESSED): ");
    printf("\n");

    get_p2pkh_address(&p2pkh, &public_key_compressed, &p2pkh_leading_zeros);
    get_p2sh_p2wpkh_address(&p2sh_p2wpkh, &public_key_compressed);
    get_p2wpkh_address(&p2wpkh, &public_key_compressed);

    print_p2pkh_address(&p2pkh, "P2PKH ADDRESS: ", p2pkh_leading_zeros);
    bnz_print(&p2sh_p2wpkh, 58, "P2SH-P2WPKH ADDRESS: ");
    print_p2wpkh_address(&p2wpkh, "P2WPKH ADDRESS: ");

    printf("\n");

    bnz_free(&public_key_compressed);
    bnz_free(&p2pkh);
    bnz_free(&p2sh_p2wpkh);
    bnz_free(&p2wpkh);

    printf("press any key to continue...");

    getchar();
}

void menu_4_3_secp256k1_functions(const char *version)
{
    int menu;
    system("cls");
    printf("%s\n\n", version);
    printf("1. Secp256k1 x coordinate validty\n");
    printf("2. Secp256k1 point addition\n");
    printf("3. Secp256k1 point doubling\n");
    printf("4. Secp256k1 scalar multiplication\n");
    printf("\n");
    menu = get_num_input(1, 0, 4);
    switch (menu) {
        case 1:
            menu_4_3_1_secp256k1_x_coordinate_validity(version);
            break;
        case 2:
            menu_4_3_2_secp256k1_point_addition(version);
            break;
        case 3:
            menu_4_3_3_secp256k1_point_doubling(version);
            break;
        case 4:
            menu_4_3_4_secp256k1_scalar_multiplication(version);
            break;
        default:
            break;
    }
}

void menu_4_3_1_secp256k1_x_coordinate_validity(const char *version)
{
    uint8_t x_str[128], base = 16;
    bnz_t x, lhs, rhs;
    APT p1, p2;

    SECP256K1 secp256k1;

    bnz_init(&x);
    bnz_init(&lhs);
    bnz_init(&rhs);
    bnz_init(&p1.x);
    bnz_init(&p1.y);
    bnz_init(&p2.x);
    bnz_init(&p2.y);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("x coordinate (press 'Enter' for random 32 bit x): ");
    get_str_input(x_str, 127);

    system("cls");
    printf("%s\n\n", version);
    printf("x coordinate: ");

    if (isalnum(x_str[0])) {
        printf("%s\n", x_str);
        printf("Base (2 - 64): ");
        base = get_num_input(2, 0, 64);
        if (base < 2) base = 16;
        bnz_set_str(&x, (const char *)x_str, base);
    } else {
        do {
            bnz_rnd(&x, 32);
        } while (bnz_cmp_bnz(&x, &secp256k1.p) != -1);
    }

    system("cls");
    printf("%s\n\n", version); 
    bnz_print(&x, base, "X COORDINATE: ");
    printf("BASE: %d\n", base);

    printf("\n");

    if (secp256k1_valid_x(secp256k1, &x) == true) {

        secp256k1_get_points_from_valid_x(secp256k1, &p1, &p2, &x);

        bnz_print(&p1.x, base, "P1.X: ");
        bnz_print(&p1.y, base, "P1.Y: ");

        printf("\n");

        secp256k1_get_rhs(secp256k1, &rhs, &p1.x);
        secp256k1_get_lhs(secp256k1, &lhs, &p1.y);

        bnz_print(&rhs, base, "P1.X^3 + 7 MOD SECP256K1.P: ");
        bnz_print(&lhs, base, "P1.Y^2     MOD SECP256K1.P: ");

        printf("\n\n");

        bnz_print(&p2.x, base, "P2.X: ");
        bnz_print(&p2.y, base, "P2.Y: ");

        printf("\n");

        secp256k1_get_rhs(secp256k1, &rhs, &p2.x);
        secp256k1_get_lhs(secp256k1, &lhs, &p2.y);

        bnz_print(&rhs, base, "P2.X^3 + 7 MOD SECP256K1.P: ");
        bnz_print(&lhs, base, "P2.Y^2     MOD SECP256K1.P: ");
    } else {
        printf("INVALID X COORDINATE\n");
    }

    printf("\n");

    printf("press any key to continue...");

    getchar();
}

void menu_4_3_2_secp256k1_point_addition(const char *version)
{
    uint8_t a_x_str[67], a_y_str[67], b_x_str[67], b_y_str[67];
    APT a, b, c;

    SECP256K1 secp256k1;

    bnz_init(&a.x);
    bnz_init(&a.y);
    bnz_init(&b.x);
    bnz_init(&b.y);
    bnz_init(&c.x);
    bnz_init(&c.y);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Point 1 x: ");
    get_str_input(a_x_str, 66);
    bnz_set_str(&a.x, (const char *)a_x_str, 16);

    printf("Point 1 y: ");
    get_str_input(a_y_str, 66);
    bnz_set_str(&a.y, (const char *)a_y_str, 16);

    if (secp256k1_valid_point(secp256k1, a) == false) { 
        system("cls");
        printf("%s\n\n", version);
        printf("This point is not on Secp256k1.\n\n");
        printf("Press any key to rerun the command with a different point.\n");
        getchar();

        bnz_free(&a.x);
        bnz_free(&a.y);
        bnz_free(&b.x);
        bnz_free(&b.y);
        bnz_free(&c.x);
        bnz_free(&c.y);

        secp256k1_free(secp256k1);

        menu_4_3_2_secp256k1_point_addition(version);
    }

    printf("Point 2 x: ");
    get_str_input(b_x_str, 66);
    bnz_set_str(&b.x, (const char *)b_x_str, 16);

    printf("Point 2 y: ");
    get_str_input(b_y_str, 66);
    bnz_set_str(&b.y, (const char *)b_y_str, 16);

    if (secp256k1_valid_point(secp256k1, b) == false) { 
        system("cls");
        printf("%s\n\n", version);
        printf("This point is not on Secp256k1.\n\n");
        printf("Press any key to rerun the command with a different point.\n");
        getchar();

        bnz_free(&a.x);
        bnz_free(&a.y);
        bnz_free(&b.x);
        bnz_free(&b.y);
        bnz_free(&c.x);
        bnz_free(&c.y);

        secp256k1_free(secp256k1);

        menu_4_3_2_secp256k1_point_addition(version);
    }

    secp256k1_point_addition(secp256k1, &a, &b, &c);

    system("cls");
    printf("%s\n\n", version);

    printf("POINT 1:\n");
    bnz_print(&a.x, 16, "x: ");
    bnz_print(&a.y, 16, "y: ");
    printf("\n");

    printf("POINT 2:\n");
    bnz_print(&b.x, 16, "x: ");
    bnz_print(&b.y, 16, "y: ");
    printf("\n");

    printf("POINT 1 + POINT 2:\n");
    bnz_print(&c.x, 16, "x: ");
    bnz_print(&c.y, 16, "y: ");
    printf("\n");

    secp256k1_free(secp256k1);

    bnz_free(&a.x);
    bnz_free(&a.y);
    bnz_free(&b.x);
    bnz_free(&b.y);
    bnz_free(&c.x);
    bnz_free(&c.y);

    printf("press any key to continue...");

    getchar();
}

void menu_4_3_3_secp256k1_point_doubling(const char *version)
{
    uint8_t a_x_str[67], a_y_str[67];
    APT a, b;

    SECP256K1 secp256k1;

    bnz_init(&a.x);
    bnz_init(&a.y);
    bnz_init(&b.x);
    bnz_init(&b.y);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Point x: ");
    get_str_input(a_x_str, 66);
    bnz_set_str(&a.x, (const char *)a_x_str, 16);

    printf("Point y: ");
    get_str_input(a_y_str, 66);
    bnz_set_str(&a.y, (const char *)a_y_str, 16);

    if (secp256k1_valid_point(secp256k1, a) == false) { 
        system("cls");
        printf("%s\n\n", version);
        printf("This point is not on Secp256k1.\n\n");
        printf("Press any key to rerun the command with a different point.\n");
        getchar();

        bnz_free(&a.x);
        bnz_free(&a.y);
        bnz_free(&b.x);
        bnz_free(&b.y);

        secp256k1_free(secp256k1);

        menu_4_3_3_secp256k1_point_doubling(version);
    }

    secp256k1_point_doubling(secp256k1, &a, &b);

    system("cls");
    printf("%s\n\n", version);

    printf("POINT:\n");
    bnz_print(&a.x, 16, "x: ");
    bnz_print(&a.y, 16, "y: ");
    printf("\n");

    printf("DOUBLED POINT:\n");
    bnz_print(&b.x, 16, "x: ");
    bnz_print(&b.y, 16, "y: ");
    printf("\n");

    bnz_free(&a.x);
    bnz_free(&a.y);
    bnz_free(&b.x);
    bnz_free(&b.y);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_4_3_4_secp256k1_scalar_multiplication(const char *version)
{
    uint8_t q_x_str[67], q_y_str[67], multiplier_str[67];
    bnz_t multiplier;
    APT q, r;

    bnz_init(&multiplier);
    bnz_init(&q.x);
    bnz_init(&q.y);
    bnz_init(&r.x);
    bnz_init(&r.y);

    SECP256K1 secp256k1;

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("q.x (press 'Enter' for Secp256k1.G.x): ");
    get_str_input(q_x_str, 66);

    if (isalnum(q_x_str[0])) {
        bnz_set_str(&q.x, (const char *)q_x_str, 16);
    } else {
        bnz_set_bnz(&q.x, &secp256k1.G.x);
    }

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&q.x, 16, "q.x: ");

    printf("q.y (press 'Enter' for Secp256k1.G.y): ");
    get_str_input(q_y_str, 66);

    if (isalnum(q_y_str[0])) {
        bnz_set_str(&q.y, (const char *)q_y_str, 16);
    } else {
        bnz_set_bnz(&q.y, &secp256k1.G.y);
    }

    if (secp256k1_valid_point(secp256k1, q) == false) { 
        system("cls");
        printf("%s\n\n", version);
        printf("This point is not on Secp256k1.\n\n");
        printf("Press any key to rerun the command with a different point.\n");
        getchar();

        bnz_free(&multiplier);
        bnz_free(&q.x);
        bnz_free(&q.y);
        bnz_free(&r.x);
        bnz_free(&r.y);

        secp256k1_free(secp256k1);

        menu_4_3_4_secp256k1_scalar_multiplication(version);
    }

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&q.x, 16, "q.x: ");
    bnz_print(&q.y, 16, "q.y: ");

    printf("\n");

    printf("Multiplier: ");
    get_str_input(multiplier_str, 66);
    bnz_set_str(&multiplier, (const char *)multiplier_str, 16);

    system("cls");
    printf("%s\n\n", version);

    bnz_print(&q.x, 16, "q.x: ");
    bnz_print(&q.y, 16, "q.y: ");

    printf("\n");

    if (secp256k1_valid_multiplier(secp256k1, &multiplier) == false) { // ensure that multiplier is in the range 0 < k < Secp256k1.n
        bnz_mod_bnz(&multiplier, &multiplier, &secp256k1.n);
        bnz_print(&multiplier, 16, "Multiplier (mod Secp256k1.n): ");
    } else {
        bnz_print(&multiplier, 16, "Multiplier: ");
    }

    system("cls");
    printf("%s\n\n", version);

    bnz_print(&q.x, 16, "q.x: ");
    bnz_print(&q.y, 16, "q.y: ");
    bnz_print(&multiplier, 16, "Multiplier: ");

    printf("\n");

    if (bnz_cmp_bnz(&q.x, &secp256k1.G.x) == 0 && bnz_cmp_bnz(&q.y, &secp256k1.G.y) == 0) { // if the point to be multiplied is the Secp256k1 generator point...
        secp256k1_jacobian_scalar_multiplication(secp256k1, &multiplier, &r); // ...use the optimized Jacobian scalar multiplication
    } else {
        secp256k1_scalar_multiplication(secp256k1, &q, &multiplier, &r); // ...otherwise use regular scalar multiplication
    }

    system("cls");
    printf("%s\n\n", version);

    bnz_print(&q.x, 16, "Q.X: ");
    bnz_print(&q.y, 16, "Q.Y: ");

    printf("\n");

    bnz_print(&multiplier, 16, "MULTIPLIER: ");

    printf("\n");

    bnz_print(&r.x, 16, "R.X: ");
    bnz_print(&r.y, 16, "R.Y: ");

    printf("\n");

    bnz_free(&multiplier);
    bnz_free(&q.x);
    bnz_free(&q.y);
    bnz_free(&r.x);
    bnz_free(&r.y);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_4_4_ecdsa_functions(const char *version)
{
    int menu;
    system("cls");
    printf("%s\n\n", version);
    printf("1. Secp256k1 ECDSA sign\n");
    printf("2. Secp256k1 ECDSA verify (signature)\n");
    printf("3. Secp256k1 ECDSA verify (r, s)\n");
    printf("\n");
    menu = get_num_input(1, 0, 3);
    switch (menu) {
        case 1:
            menu_4_4_1_ecdsa_sign(version);
            break;
        case 2:
            menu_4_4_2_ecdsa_verify_signature(version);
            break;
        case 3:
            menu_4_4_3_ecdsa_verify_r_s(version);
            break;
        default:
            break;
    }
}

void menu_4_4_1_ecdsa_sign(const char *version)
{
    char private_key_str[67], message_hash_str[67];
    uint32_t nonce_type = 0;
    bnz_t private_key, message_hash, r, s, signature;
    SECP256K1 secp256k1;

    bnz_init(&private_key);
    bnz_init(&message_hash);
    bnz_init(&r);
    bnz_init(&s);
    bnz_init(&signature);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Private key: ");
    get_str_input(private_key_str, 66);
    bnz_set_str(&private_key, (const char *)private_key_str, 16);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&private_key, 16, "Private key: ");

    printf("Message hash: ");
    get_str_input(message_hash_str, 66);
    bnz_set_str(&message_hash, (const char *)message_hash_str, 16);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&private_key, 16, "Private key: ");
    bnz_print(&message_hash, 16, "Message hash: ");

    printf("Nonce: deterministic (0) or random (1): ");
    nonce_type = get_num_input(1, 0, 1);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&private_key, 16, "Private key: ");
    bnz_print(&message_hash, 16, "Message hash: ");
    if (nonce_type == 0) {
        printf("Nonce: deterministic\n");
    } else {
        printf("Nonce: random\n");
    }
    printf("\n");

    secp256k1_ecdsa_sign(secp256k1, &private_key, &message_hash, &r, &s, nonce_type);
    secp256k1_ecdsa_get_signature_from_r_s(&r, &s, &signature);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&private_key, 16, "PRIVATE KEY: ");
    bnz_print(&message_hash, 16, "MESSAGE HASH: ");
    if (nonce_type == 0) {
        printf("NONCE: DETERMINISTIC\n");
    } else {
        printf("NONCE: RANDOM\n");
    }
    printf("\n");

    bnz_print(&signature, 16, "ECDSA SIGNATURE: ");
    bnz_print(&r, 16, "ECDSA SIGNATURE R: ");
    bnz_print(&s, 16, "ECDSA SIGNATURE S: ");
    printf("\n");

    bnz_free(&private_key);
    bnz_free(&message_hash);
    bnz_free(&r);
    bnz_free(&s);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_4_4_2_ecdsa_verify_signature(const char *version)
{
    char public_key_compressed_str[69], message_hash_str[67], signature_str[147]; // 0x + (2 * (1 + 1 + 1 + 1 + 33 + 1 + 1 + 33)) + 0x0
    bool verified;
    bnz_t public_key_compressed, message_hash, signature;
    SECP256K1 secp256k1;

    bnz_init(&public_key_compressed);
    bnz_init(&message_hash);
    bnz_init(&signature);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Public key (compressed): ");
    get_str_input(public_key_compressed_str, 68);
    bnz_set_str(&public_key_compressed, (const char *)public_key_compressed_str, 16);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&public_key_compressed, 16, "Public key (compressed): ");

    printf("Message hash: ");
    get_str_input(message_hash_str, 66);
    bnz_set_str(&message_hash, (const char *)message_hash_str, 16);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&public_key_compressed, 16, "Public key (compressed): ");
    bnz_print(&message_hash, 16, "Message hash: ");

    printf("ECDSA signature: ");
    get_str_input(signature_str, 146);
    bnz_set_str(&signature, (const char *)signature_str, 16);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&public_key_compressed, 16, "Public key (compressed): ");
    bnz_print(&message_hash, 16, "Message hash: ");
    bnz_print(&signature, 16, "ECDSA signature: ");
    printf("\n");

    verified = secp256k1_ecdsa_verify_from_signature(secp256k1, &public_key_compressed, &message_hash, &signature);

    bnz_free(&public_key_compressed);
    bnz_free(&message_hash);
    bnz_free(&signature);

    secp256k1_free(secp256k1);

    if (verified == true) {
        printf("VERIFICATION SUCCEEDED\n");
    } else {
        printf("VERIFICATION FAILED\n");
    }
    printf("\n");

    printf("press any key to continue...");

    getchar();
}

void menu_4_4_3_ecdsa_verify_r_s(const char *version)
{
    char public_key_compressed_str[69], message_hash_str[67], r_str[67], s_str[67];
    bool verified;
    bnz_t public_key_compressed, message_hash, r, s;
    SECP256K1 secp256k1;

    bnz_init(&public_key_compressed);
    bnz_init(&message_hash);
    bnz_init(&r);
    bnz_init(&s);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Public key (compressed): ");
    get_str_input(public_key_compressed_str, 68);
    bnz_set_str(&public_key_compressed, (const char *)public_key_compressed_str, 16);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&public_key_compressed, 16, "Public key (compressed): ");

    printf("Message hash: ");
    get_str_input(message_hash_str, 66);
    bnz_set_str(&message_hash, (const char *)message_hash_str, 16);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&public_key_compressed, 16, "Public key (compressed): ");
    bnz_print(&message_hash, 16, "Message hash: ");

    printf("ECDSA signature r: ");
    get_str_input(r_str, 66);
    bnz_set_str(&r, (const char *)r_str, 16);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&public_key_compressed, 16, "Public key (compressed): ");
    bnz_print(&message_hash, 16, "Message hash: ");
    bnz_print(&r, 16, "ECDSA signature r: ");

    printf("ECDSA signature s: ");
    get_str_input(s_str, 66);
    bnz_set_str(&s, s_str, 16);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&public_key_compressed, 16, "Public key (compressed): ");
    bnz_print(&message_hash, 16, "Message hash: ");
    bnz_print(&r, 16, "ECDSA signature r: ");
    bnz_print(&s, 16, "ECDSA signature s: ");
    printf("\n");

    verified = secp256k1_ecdsa_verify_from_r_s(secp256k1, &public_key_compressed, &message_hash, &r, &s);

    bnz_free(&public_key_compressed);
    bnz_free(&message_hash);
    bnz_free(&r);
    bnz_free(&s);

    secp256k1_free(secp256k1);

    if (verified == true) {
        printf("VERIFICATION SUCCEEDED\n");
    } else {
        printf("VERIFICATION FAILED\n");
    }
    printf("\n");

    printf("press any key to continue...");

    getchar();
}

void menu_5_file_hash_functions(const char *version)
{
    int menu;
    system("cls");
    printf("%s\n\n", version);
    printf("1. RIPEMD160\n");
    printf("2. SHA256\n");
    printf("3. SHA512\n");
    printf("\n");
    menu = get_num_input(1, 0, 3);
    switch (menu) {
        case 1:
            get_file_hash(version, 1);
            break;
        case 2:
            get_file_hash(version, 2);
            break;
        case 3:
            get_file_hash(version, 3);
            break;
        default:
            break;
    }
}

/* MAIN */

int main()
{
    static char *version = "bitcoin_math\nv0.29, 2026-08-29";
    int menu, running = 1;
    while (running) {
        system("cls");
        printf("%s\n\n", version);
        printf("1. Master keys\n");
        printf("2. Child keys\n");
        printf("3. Base converter\n");
        printf("4. Functions\n");
        printf("5. File hash functions\n");
        printf("\n");
        menu = get_num_input(1, 0, 5);
        switch (menu) {
            case 1:
                menu_1_master_keys(version);
                break;
            case 2:
                menu_2_child_keys(version);
                break;
            case 3:
                menu_3_base_converter(version);
                break;
            case 4:
                menu_4_functions(version);
                break;
            case 5:
                menu_5_file_hash_functions(version);
                break;
            default:
                running = 0;
                break;
        }
    }
    return 0;
}
