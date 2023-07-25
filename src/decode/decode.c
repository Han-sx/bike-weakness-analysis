/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 *
 * [1] The optimizations are based on the description developed in the paper:
 *     Drucker, Nir, and Shay Gueron. 2019. “A Toolbox for Software Optimization
 *     of QC-MDPC Code-Based Cryptosystems.” Journal of Cryptographic Engineering,
 *     January, 1–17. https://doi.org/10.1007/s13389-018-00200-4.
 *
 * [2] The decoder algorithm is the Black-Gray decoder in
 *     the early submission of CAKE (due to N. Sandrier and R Misoczki).
 *
 * [3] The analysis for the constant time implementation is given in
 *     Drucker, Nir, Shay Gueron, and Dusan Kostic. 2019.
 *     “On Constant-Time QC-MDPC Decoding with Negligible Failure Rate.”
 *     Cryptology EPrint Archive, 2019. https://eprint.iacr.org/2019/1289.
 *
 * [4] it was adapted to BGF in:
 *     Drucker, Nir, Shay Gueron, and Dusan Kostic. 2019.
 *     “QC-MDPC decoders with several shades of gray.”
 *     Cryptology EPrint Archive, 2019. To be published.
 *
 * [5] Chou, T.: QcBits: Constant-Time Small-Key Code-Based Cryptography.
 *     In: Gier-lichs, B., Poschmann, A.Y. (eds.) Cryptographic Hardware
 *     and Embedded Systems– CHES 2016. pp. 280–300. Springer Berlin Heidelberg,
 *     Berlin, Heidelberg (2016)
 *
 * [6] The rotate512_small funciton is a derivative of the code described in:
 *     Guimarães, Antonio, Diego F Aranha, and Edson Borin. 2019.
 *     “Optimized Implementation of QC-MDPC Code-Based Cryptography.”
 *     Concurrency and Computation: Practice and Experience 31 (18):
 *     e5089. https://doi.org/10.1002/cpe.5089.
 */

#include "decode.h"
#include "cleanup.h"
#include "decode_internal.h"
#include "gf2x.h"
#include "utilities.h"
#include <stdio.h>

// Decoding (bit-flipping) parameter
#if defined(BG_DECODER)
#  if(LEVEL == 1)
#    define MAX_IT 3
#  elif(LEVEL == 3)
#    define MAX_IT 4
#  else
#    error "Level can only be 1/3"
#  endif
#elif defined(BGF_DECODER)
#  define MAX_IT 5
#endif

// 当 SAVE_MOD = 0 时保存所有(密钥，e，upc)，1 保存正确所有，2 保存错误所有, 3
// 仅保存 upc 正确, 4 仅保存 upc 错误, 其他不保存
#define SAVE_MOD 5

// 是否保存 fake_upc, 0 保存所有，1 保存正确，2 保存错误， 其他不保存
// fake_upc 是由 [hinv, h] 模拟 [h0, h1] 获得：
// [e0, e1] * [hinv, h] = fake_s; fake_s * [hinv, h] = fake_upc
#define SAVE_FAKE_UPC 3

// 是否构造保存 s 的整数域值(这里会保存两行 e0*h0^T 和 e1*h1^T 需要后期合并) 1
// 保存, 其他不保存
#define SAVE_S_INT_MOD 1

// 用于计算出upc切片的值并保存在文件中
_INLINE_ void compute_upc_and_save_test(IN upc_t upc)
{
  // ---- test ---- 将 upc 切片的值计算出来并保存
  uint64_t mask_1 = 1;
  // 处理前 R_QW - 1 位
  // 将每层累计得到的 upc_i 写入文件
  FILE *fp_2;
  fp_2 = fopen("weak_key", "a");
  for(uint32_t i_upc = 0; i_upc < R_QWORDS - 1; i_upc++) {
    for(uint64_t location = 1; location != 0; location <<= 1) {
      // 用于保存每个upc[i]的值
      uint32_t upc_i = 0;
      for(uint32_t location_s = 1, i_upc_s = 0; i_upc_s < SLICES - 1;
          i_upc_s++, location_s <<= 1) {
        if((upc.slice[i_upc_s].u.qw[i_upc] & location) != 0) {
          upc_i += location_s;
        }
      }
      fprintf(fp_2, "%u ", upc_i);
    }
  }
  // 处理最后 R_BITS - (R_QW - 1) * 64 位
  for(uint64_t location = 1;
      location < (mask_1 << (R_BITS - (R_QWORDS - 1) * 64)); location <<= 1) {
    // 用于保存每个upc[i]的值
    uint32_t upc_i = 0;
    for(uint32_t location_s = 1, i_upc_s = 0; i_upc_s < SLICES - 1;
        i_upc_s++, location_s <<= 1) {
      if((upc.slice[i_upc_s].u.qw[R_QWORDS - 1] & location) != 0) {
        upc_i += location_s;
      }
    }
    fprintf(fp_2, "%u ", upc_i);
  }
  fclose(fp_2);
}

// 换行函数
void write_wrap(char *filename)
{
  FILE *fp_LE_test_1;
  fp_LE_test_1 = fopen(filename, "a");
  fprintf(fp_LE_test_1, "\n");
  fclose(fp_LE_test_1);
}

ret_t compute_syndrome(OUT syndrome_t      *syndrome,
                       IN const pad_r_t    *c0,
                       IN const pad_r_t    *h0,
                       IN const decode_ctx *ctx)
{
  DEFER_CLEANUP(pad_r_t pad_s, pad_r_cleanup);

  gf2x_mod_mul(&pad_s, c0, h0);

  bike_memcpy((uint8_t *)syndrome->qw, pad_s.val.raw, R_BYTES);
  ctx->dup(syndrome);

  return SUCCESS;
}

_INLINE_ ret_t recompute_syndrome(OUT syndrome_t      *syndrome,
                                  IN const pad_r_t    *c0,
                                  IN const pad_r_t    *h0,
                                  IN const pad_r_t    *pk,
                                  IN const e_t        *e,
                                  IN const decode_ctx *ctx)
{
  DEFER_CLEANUP(pad_r_t tmp_c0, pad_r_cleanup);
  DEFER_CLEANUP(pad_r_t e0 = {0}, pad_r_cleanup);
  DEFER_CLEANUP(pad_r_t e1 = {0}, pad_r_cleanup);

  e0.val = e->val[0];
  e1.val = e->val[1];

  // tmp_c0 = pk * e1 + c0 + e0
  gf2x_mod_mul(&tmp_c0, &e1, pk);
  gf2x_mod_add(&tmp_c0, &tmp_c0, c0);
  gf2x_mod_add(&tmp_c0, &tmp_c0, &e0);

  // Recompute the syndrome using the updated ciphertext
  GUARD(compute_syndrome(syndrome, &tmp_c0, h0, ctx));

  return SUCCESS;
}

_INLINE_ uint8_t get_threshold(IN const syndrome_t *s)
{
  bike_static_assert(sizeof(*s) >= sizeof(r_t), syndrome_is_large_enough);

  const uint32_t syndrome_weight = r_bits_vector_weight((const r_t *)s->qw);

  // The equations below are defined in BIKE's specification p. 16, Section 5.2
  uint32_t       thr  = THRESHOLD_COEFF0 + (THRESHOLD_COEFF1 * syndrome_weight);
  const uint32_t mask = secure_l32_mask(thr, THRESHOLD_MIN);
  thr = (u32_barrier(mask) & thr) | (u32_barrier(~mask) & THRESHOLD_MIN);

  DMSG("    Threshold: %d\n", thr);
  return thr;
}

// Calculate the Unsatisfied Parity Checks (UPCs) and update the errors
// vector (e) accordingly. In addition, update the black and gray errors vector
// with the relevant values.
_INLINE_ void find_err1(OUT upc_all_t                 *upc_out,
                        OUT e_t                       *e,
                        OUT e_t                       *black_e,
                        OUT e_t                       *gray_e,
                        IN const syndrome_t           *syndrome,
                        IN const compressed_idx_d_ar_t wlist,
                        IN const uint8_t               threshold,
                        IN const decode_ctx           *ctx)
{
  // This function uses the bit-slice-adder methodology of [5]:
  DEFER_CLEANUP(syndrome_t rotated_syndrome = {0}, syndrome_cleanup);
  DEFER_CLEANUP(upc_t upc, upc_cleanup);

  for(uint32_t i = 0; i < N0; i++) {
    // UPC must start from zero at every iteration
    bike_memset(&upc, 0, sizeof(upc));

    // 1) Right-rotate the syndrome for every secret key set bit index
    //    Then slice-add it to the UPC array.
    for(size_t j = 0; j < D; j++) {
      ctx->rotate_right(&rotated_syndrome, syndrome, wlist[i].val[j]);
      ctx->bit_sliced_adder(&upc, &rotated_syndrome, LOG2_MSB(j + 1));
    }

    // 保存 upc 到 upc_out
    for(uint8_t slice_i = 0; slice_i < SLICES; slice_i++) {
      upc_out->val[i].slice[slice_i] = upc.slice[slice_i];
    }

    // 2) Subtract the threshold from the UPC counters
    ctx->bit_slice_full_subtract(&upc, threshold);

    // 3) Update the errors and the black errors vectors.
    //    The last slice of the UPC array holds the MSB of the accumulated values
    //    minus the threshold. Every zero bit indicates a potential error bit.
    //    The errors values are stored in the black array and xored with the
    //    errors Of the previous iteration.
    const r_t *last_slice = &(upc.slice[SLICES - 1].u.r.val);
    for(size_t j = 0; j < R_BYTES; j++) {
      const uint8_t sum_msb  = (~last_slice->raw[j]);
      black_e->val[i].raw[j] = sum_msb;
      e->val[i].raw[j] ^= sum_msb;
    }

    // Ensure that the padding bits (upper bits of the last byte) are zero so
    // they will not be included in the multiplication and in the hash function.
    e->val[i].raw[R_BYTES - 1] &= LAST_R_BYTE_MASK;

    // 4) Calculate the gray error array by adding "DELTA" to the UPC array.
    //    For that we reuse the rotated_syndrome variable setting it to all "1".
    for(size_t l = 0; l < DELTA; l++) {
      bike_memset((uint8_t *)rotated_syndrome.qw, 0xff, R_BYTES);
      ctx->bit_sliced_adder(&upc, &rotated_syndrome, SLICES);
    }

    // 5) Update the gray list with the relevant bits that are not
    //    set in the black list.
    for(size_t j = 0; j < R_BYTES; j++) {
      const uint8_t sum_msb = (~last_slice->raw[j]);
      gray_e->val[i].raw[j] = (~(black_e->val[i].raw[j])) & sum_msb;
    }
  }
}

// Recalculate the UPCs and update the errors vector (e) according to it
// and to the black/gray vectors.
_INLINE_ void find_err2(OUT e_t                       *e,
                        IN e_t                        *pos_e,
                        IN const syndrome_t           *syndrome,
                        IN const compressed_idx_d_ar_t wlist,
                        IN const uint8_t               threshold,
                        IN const decode_ctx           *ctx)
{
  DEFER_CLEANUP(syndrome_t rotated_syndrome = {0}, syndrome_cleanup);
  DEFER_CLEANUP(upc_t upc, upc_cleanup);

  for(uint32_t i = 0; i < N0; i++) {
    // UPC must start from zero at every iteration
    bike_memset(&upc, 0, sizeof(upc));

    // 1) Right-rotate the syndrome, for every index of a set bit in the secret
    // key. Then slice-add it to the UPC array.
    for(size_t j = 0; j < D; j++) {
      ctx->rotate_right(&rotated_syndrome, syndrome, wlist[i].val[j]);
      ctx->bit_sliced_adder(&upc, &rotated_syndrome, LOG2_MSB(j + 1));
    }

    // 2) Subtract the threshold from the UPC counters
    ctx->bit_slice_full_subtract(&upc, threshold);

    // 3) Update the errors vector.
    //    The last slice of the UPC array holds the MSB of the accumulated values
    //    minus the threshold. Every zero bit indicates a potential error bit.
    const r_t *last_slice = &(upc.slice[SLICES - 1].u.r.val);
    for(size_t j = 0; j < R_BYTES; j++) {
      const uint8_t sum_msb = (~last_slice->raw[j]);
      e->val[i].raw[j] ^= (pos_e->val[i].raw[j] & sum_msb);
    }

    // Ensure that the padding bits (upper bits of the last byte) are zero, so
    // they are not included in the multiplication, and in the hash function.
    e->val[i].raw[R_BYTES - 1] &= LAST_R_BYTE_MASK;
  }
}

ret_t decode(OUT e_t          *e,
             IN const ct_t    *ct,
             IN const sk_t    *sk,
             IN uint32_t      *error_count,
             IN uint32_t      *right_count,
             IN const pad_e_t *R_e,
             IN unsigned char *fake_sk)
{
  // Initialize the decode methods struct
  decode_ctx ctx;
  decode_ctx_init(&ctx);

  DEFER_CLEANUP(e_t black_e = {0}, e_cleanup);
  DEFER_CLEANUP(e_t gray_e = {0}, e_cleanup);

  DEFER_CLEANUP(pad_r_t c0 = {0}, pad_r_cleanup);
  DEFER_CLEANUP(pad_r_t h0 = {0}, pad_r_cleanup);
  pad_r_t pk = {0};

  // Pad ciphertext (c0), secret key (h0), and public key (h)
  c0.val = ct->c0;
  h0.val = sk->bin[0];
  pk.val = sk->pk;

  // 计算 fake_upc
  upc_all_t upc_fake_out = {0};
  if(SAVE_FAKE_UPC == 0 || SAVE_FAKE_UPC == 1 || SAVE_FAKE_UPC == 2) {
    // 将 fake_sk 获取
    DEFER_CLEANUP(aligned_sk_t l_fake_sk, sk_cleanup);
    bike_memcpy(&l_fake_sk, fake_sk, sizeof(l_fake_sk));

    DEFER_CLEANUP(pad_r_t e0_tmp = {0}, pad_r_cleanup);
    DEFER_CLEANUP(pad_r_t e1_tmp = {0}, pad_r_cleanup);
    DEFER_CLEANUP(pad_r_t hinv_tmp = {0}, pad_r_cleanup);
    DEFER_CLEANUP(pad_r_t h_tmp = {0}, pad_r_cleanup);
    DEFER_CLEANUP(pad_r_t e0_mul_hinv = {0}, pad_r_cleanup);
    DEFER_CLEANUP(pad_r_t e1_mul_h = {0}, pad_r_cleanup);
    DEFER_CLEANUP(pad_r_t s_tmp = {0}, pad_r_cleanup);
    e0_tmp.val   = R_e->val[0].val;
    e1_tmp.val   = R_e->val[1].val;
    hinv_tmp.val = l_fake_sk.bin[0];
    h_tmp.val    = l_fake_sk.bin[1];

    // 进行 e0 * hinv + e1 * h 运算
    gf2x_mod_mul(&e0_mul_hinv, &e0_tmp, &hinv_tmp);
    gf2x_mod_mul(&e1_mul_h, &e1_tmp, &h_tmp);
    gf2x_mod_add(&s_tmp, &e0_mul_hinv, &e1_mul_h);
    DEFER_CLEANUP(syndrome_t s_fake = {0}, syndrome_cleanup);
    bike_memcpy((uint8_t *)s_fake.qw, s_tmp.val.raw, R_BYTES);
    decode_ctx ctx_fake;
    decode_ctx_init(&ctx_fake);
    ctx_fake.dup(&s_fake);

    // 计算 [h_inv, h] 的首行重量
    uint64_t hinv_w = r_bits_vector_weight((r_t *)&l_fake_sk.bin[0].raw);
    // printf("hinv 的重量: %lu\n", hinv_w);
    uint64_t h_w = r_bits_vector_weight((r_t *)&l_fake_sk.bin[1].raw);
    // printf("h 的重量: %lu\n", h_w);

    // 构造 h 和 hinv 的首行位置，然后用 类似方法旋转获取 upc
    // 构造数组用于保存首行位置 wlist_fake_0 wlist_fake_1
    uint32_t wlist_fake_0[hinv_w];
    uint32_t wlist_fake_1[h_w];
    memset(wlist_fake_0, 0, sizeof(wlist_fake_0));
    memset(wlist_fake_1, 0, sizeof(wlist_fake_1));

    uint32_t count_0    = 0;
    uint32_t location_0 = 0;
    for(int i_0 = 0; i_0 < R_BYTES; i_0++) {
      for(uint8_t mask_wlist = 1; mask_wlist != 0; mask_wlist <<= 1) {
        if(location_0 == R_BITS) {
          break;
        }
        if((l_fake_sk.bin[0].raw[i_0] & mask_wlist) != 0) {
          wlist_fake_0[count_0] = location_0;
          count_0++;
        }
        location_0++;
      }
    }

    uint32_t count_1    = 0;
    uint32_t location_1 = 0;
    for(int i_1 = 0; i_1 < R_BYTES; i_1++) {
      for(uint8_t mask_wlist = 1; mask_wlist != 0; mask_wlist <<= 1) {
        if(location_1 == R_BITS) {
          break;
        }
        if((l_fake_sk.bin[1].raw[i_1] & mask_wlist) != 0) {
          wlist_fake_1[count_1] = location_1;
          count_1++;
        }
        location_1++;
      }
    }

    DEFER_CLEANUP(syndrome_t rotated_syndrome = {0}, syndrome_cleanup);
    DEFER_CLEANUP(upc_t upc_fake, upc_cleanup);
    for(uint32_t i = 0; i < N0; i++) {

      // UPC must start from zero at every iteration
      bike_memset(&upc_fake, 0, sizeof(upc_fake));

      // 1) Right-rotate the syndrome for every secret key set bit index
      //    Then slice-add it to the UPC array.
      if(i == 0) {
        for(size_t j = 0; j < hinv_w; j++) {
          ctx_fake.rotate_right(&rotated_syndrome, &s_fake, wlist_fake_0[j]);
          ctx_fake.bit_sliced_adder(&upc_fake, &rotated_syndrome,
                                    LOG2_MSB(j + 1));
        }
      } else {
        for(size_t j = 0; j < h_w; j++) {
          ctx_fake.rotate_right(&rotated_syndrome, &s_fake, wlist_fake_1[j]);
          ctx_fake.bit_sliced_adder(&upc_fake, &rotated_syndrome,
                                    LOG2_MSB(j + 1));
        }
      }

      // 保存 upc 到 upc_out
      for(uint8_t slice_i = 0; slice_i < SLICES; slice_i++) {
        upc_fake_out.val[i].slice[slice_i] = upc_fake.slice[slice_i];
      }
    }
  }

  DEFER_CLEANUP(syndrome_t s = {0}, syndrome_cleanup);
  DMSG("  Computing s.\n");
  GUARD(compute_syndrome(&s, &c0, &h0, &ctx));
  ctx.dup(&s);

  // Reset (init) the error because it is xored in the find_err functions.
  bike_memset(e, 0, sizeof(*e));

  // 用于保存 upc 的值
  upc_all_t weak_upc[MAX_IT + 2] = {0};

  for(uint32_t iter = 0; iter < MAX_IT; iter++) {
    const uint8_t threshold = get_threshold(&s);

    DMSG("    Iteration: %d\n", iter);
    DMSG("    Weight of e: %lu\n",
         r_bits_vector_weight(&e->val[0]) + r_bits_vector_weight(&e->val[1]));
    DMSG("    Weight of syndrome: %lu\n", r_bits_vector_weight((r_t *)s.qw));

    find_err1(&weak_upc[iter], e, &black_e, &gray_e, &s, sk->wlist, threshold,
              &ctx);
    GUARD(recompute_syndrome(&s, &c0, &h0, &pk, e, &ctx));
#if defined(BGF_DECODER)
    if(iter >= 1) {
      continue;
    }
#endif
    DMSG("    Weight of e: %lu\n",
         r_bits_vector_weight(&e->val[0]) + r_bits_vector_weight(&e->val[1]));
    DMSG("    Weight of syndrome: %lu\n", r_bits_vector_weight((r_t *)s.qw));

    find_err2(e, &black_e, &s, sk->wlist, ((D + 1) / 2) + 1, &ctx);
    GUARD(recompute_syndrome(&s, &c0, &h0, &pk, e, &ctx));

    DMSG("    Weight of e: %lu\n",
         r_bits_vector_weight(&e->val[0]) + r_bits_vector_weight(&e->val[1]));
    DMSG("    Weight of syndrome: %lu\n", r_bits_vector_weight((r_t *)s.qw));

    find_err2(e, &gray_e, &s, sk->wlist, ((D + 1) / 2) + 1, &ctx);
    GUARD(recompute_syndrome(&s, &c0, &h0, &pk, e, &ctx));
  }

  // 保存文件名
  char filename[20] = "weak_key";

  // 检查是否保存整数域的 s 值
  if(SAVE_S_INT_MOD == 1) {
    // ========== 开始构造 s 的有限域存储 ==========

    // 新建 sk 的转置
    sk_t sk_transpose = {0};

    // 构造 sk 转置 sk_transpose, 获取 sk 转置的首行索引
    // 𝜑(A)' = a0 + ar-1X + ar-2X^2 ...
    for(uint8_t i = 0; i < N0; i++) {
      for(uint8_t i_DV = 0; i_DV < D; i_DV++) {
        if(sk->wlist[i].val[i_DV] != 0) {
          sk_transpose.wlist[i].val[i_DV] = R_BITS - sk->wlist[i].val[i_DV];
        } else {
          sk_transpose.wlist[i].val[i_DV] = sk->wlist[i].val[i_DV];
        }
      }
    }

    // 用 e 和 sk_transpose 进行有限域相乘，并保存在 upc 结构中
    // 构造 upc_eh_01_out 保存 e0*h0^T 和 e1*h0^T
    upc_all_t upc_eh_01_out = {0};
    DEFER_CLEANUP(syndrome_t e_0_s = {0}, syndrome_cleanup);
    DEFER_CLEANUP(syndrome_t e_1_s = {0}, syndrome_cleanup);
    bike_memcpy((uint8_t *)e_0_s.qw, R_e->val[0].val.raw, R_BYTES);
    bike_memcpy((uint8_t *)e_1_s.qw, R_e->val[1].val.raw, R_BYTES);
    decode_ctx ctx_e_s;
    decode_ctx_init(&ctx_e_s);
    ctx_e_s.dup(&e_0_s);
    ctx_e_s.dup(&e_1_s);

    DEFER_CLEANUP(syndrome_t rotated_syndrome = {0}, syndrome_cleanup);
    DEFER_CLEANUP(upc_t upc_eh_0, upc_cleanup);
    DEFER_CLEANUP(upc_t upc_eh_1, upc_cleanup);
    for(uint32_t i = 0; i < N0; i++) {

      // UPC must start from zero at every iteration
      bike_memset(&upc_eh_0, 0, sizeof(upc_eh_0));
      bike_memset(&upc_eh_1, 0, sizeof(upc_eh_1));

      // 1) Right-rotate the syndrome for every secret key set bit index
      //    Then slice-add it to the UPC array.
      if(i == 0) {
        for(size_t j = 0; j < D; j++) {
          ctx_e_s.rotate_right(&rotated_syndrome, &e_0_s,
                               sk_transpose.wlist[i].val[j]);
          ctx_e_s.bit_sliced_adder(&upc_eh_0, &rotated_syndrome, LOG2_MSB(j + 1));
        }
        // 保存 upc 到 upc_out
        for(uint8_t slice_i = 0; slice_i < SLICES; slice_i++) {
          upc_eh_01_out.val[i].slice[slice_i] = upc_eh_0.slice[slice_i];
        }
      } else {
        for(size_t j = 0; j < D; j++) {
          ctx_e_s.rotate_right(&rotated_syndrome, &e_1_s,
                               sk_transpose.wlist[i].val[j]);
          ctx_e_s.bit_sliced_adder(&upc_eh_1, &rotated_syndrome, LOG2_MSB(j + 1));
        }
        // 保存 upc 到 upc_out
        for(uint8_t slice_i = 0; slice_i < SLICES; slice_i++) {
          upc_eh_01_out.val[i].slice[slice_i] = upc_eh_1.slice[slice_i];
        }
      }
    }
    // 保存到文件
    compute_upc_and_save_test(upc_eh_01_out.val[0]);
    write_wrap(filename);
    compute_upc_and_save_test(upc_eh_01_out.val[1]);
    write_wrap(filename);
  }

  // 检查 fake_upc
  if(SAVE_FAKE_UPC == 0) {
    // 保存到文件
    compute_upc_and_save_test(upc_fake_out.val[0]);
    compute_upc_and_save_test(upc_fake_out.val[1]);
    // 换行
    write_wrap(filename);
  } else if(SAVE_FAKE_UPC == 1) {
    if(r_bits_vector_weight((r_t *)s.qw) == 0) {
      // 译码正确保存
      compute_upc_and_save_test(upc_fake_out.val[0]);
      compute_upc_and_save_test(upc_fake_out.val[1]);
      // 换行
      write_wrap(filename);
    }
  } else if(SAVE_FAKE_UPC == 2) {
    if(r_bits_vector_weight((r_t *)s.qw) > 0) {
      // 译码错误保存
      compute_upc_and_save_test(upc_fake_out.val[0]);
      compute_upc_and_save_test(upc_fake_out.val[1]);
      // 换行
      write_wrap(filename);
    }
  }

  // 设置保存类型
  // 当 SAVE_MOD = 0 时保存所有，1 保存正确，2 保存错误，其他不保存
  if(SAVE_MOD == 0) {
    // 保存当前密钥
    fprintf_LE_test((const uint64_t *)sk->bin[0].raw, R_BITS);
    fprintf_LE_test((const uint64_t *)sk->bin[1].raw, R_BITS);
    // 换行
    write_wrap(filename);
    // 保存真实 e
    fprintf_LE_test((const uint64_t *)R_e->val[0].val.raw, R_BITS);
    fprintf_LE_test((const uint64_t *)R_e->val[1].val.raw, R_BITS);
    // 换行
    write_wrap(filename);
    // 写入 upc
    compute_upc_and_save_test(weak_upc[0].val[0]);
    compute_upc_and_save_test(weak_upc[0].val[1]);
    // 换行
    write_wrap(filename);
    // 写入 flag
    FILE *fp_LE_test_2;
    fp_LE_test_2 = fopen("weak_key_flag", "a");
    if(r_bits_vector_weight((r_t *)s.qw) > 0) {
      // 如果译码失败
      fprintf(fp_LE_test_2, "0\n");
    } else {
      // 如果译码成功
      fprintf(fp_LE_test_2, "1\n");
    }
    fclose(fp_LE_test_2);
  } else if(SAVE_MOD == 1) {
    if(r_bits_vector_weight((r_t *)s.qw) == 0) {
      // 保存当前密钥
      fprintf_LE_test((const uint64_t *)sk->bin[0].raw, R_BITS);
      fprintf_LE_test((const uint64_t *)sk->bin[1].raw, R_BITS);
      // 换行
      write_wrap(filename);
      // 保存真实 e
      fprintf_LE_test((const uint64_t *)R_e->val[0].val.raw, R_BITS);
      fprintf_LE_test((const uint64_t *)R_e->val[1].val.raw, R_BITS);
      // 换行
      write_wrap(filename);
      // 写入 upc
      compute_upc_and_save_test(weak_upc[0].val[0]);
      compute_upc_and_save_test(weak_upc[0].val[1]);
      // 换行
      write_wrap(filename);
      // 写入 flag
      FILE *fp_LE_test_2;
      fp_LE_test_2 = fopen("weak_key_flag", "a");
      fprintf(fp_LE_test_2, "1\n");
      fclose(fp_LE_test_2);
    }
  } else if(SAVE_MOD == 2) {
    if(r_bits_vector_weight((r_t *)s.qw) > 0) {
      // 保存当前密钥
      fprintf_LE_test((const uint64_t *)sk->bin[0].raw, R_BITS);
      fprintf_LE_test((const uint64_t *)sk->bin[1].raw, R_BITS);
      // 换行
      write_wrap(filename);
      // 保存真实 e
      fprintf_LE_test((const uint64_t *)R_e->val[0].val.raw, R_BITS);
      fprintf_LE_test((const uint64_t *)R_e->val[1].val.raw, R_BITS);
      // 换行
      write_wrap(filename);
      // 写入 upc
      compute_upc_and_save_test(weak_upc[0].val[0]);
      compute_upc_and_save_test(weak_upc[0].val[1]);
      // 换行
      write_wrap(filename);
      // 写入 flag
      FILE *fp_LE_test_2;
      fp_LE_test_2 = fopen("weak_key_flag", "a");
      fprintf(fp_LE_test_2, "0\n");
      fclose(fp_LE_test_2);
    }
  } else if(SAVE_MOD == 3) {
    if(r_bits_vector_weight((r_t *)s.qw) == 0) {
      // 写入 upc
      compute_upc_and_save_test(weak_upc[0].val[0]);
      compute_upc_and_save_test(weak_upc[0].val[1]);
      // 换行
      write_wrap(filename);
    }
  } else if(SAVE_MOD == 4) {
    if(r_bits_vector_weight((r_t *)s.qw) > 0) {
      // 写入 upc
      compute_upc_and_save_test(weak_upc[0].val[0]);
      compute_upc_and_save_test(weak_upc[0].val[1]);
      // 换行
      write_wrap(filename);
    }
  }

  if(r_bits_vector_weight((r_t *)s.qw) > 0) {
    *error_count = *error_count + 1;
    BIKE_ERROR(E_DECODING_FAILURE);
  }
  *right_count = *right_count + 1;
  return SUCCESS;
}
