/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include "types.h"

ret_t decode(OUT e_t       *e,
             IN const ct_t *ct,
             IN const sk_t *sk,
             IN uint32_t   *error_count,
             IN uint32_t   *right_count,
             IN const pad_e_t *R_e,
             IN unsigned char *fake_sk);
