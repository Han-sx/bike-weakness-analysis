/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include "types.h"

////////////////////////////////////////////////////////////////
// Below three APIs (keygen, encaps, decaps) are defined by NIST:
////////////////////////////////////////////////////////////////
// Keygenerate - pk is the public key,
//               sk is the private key,
int crypto_kem_keypair(OUT unsigned char *pk,
                       OUT unsigned char *sk,
                       OUT unsigned char *fake_sk);

// Encapsulate - pk is the public key,
//               ct is a key encapsulation message (ciphertext),
//               ss is the shared secret.
int crypto_kem_enc(OUT unsigned char      *ct,
                   OUT unsigned char      *ss,
                   IN const unsigned char *pk,
                   IN pad_e_t             *R_e,
                   IN int                 *flag,
                   IN m_t                 *m_in);

// Decapsulate - ct is a key encapsulation message (ciphertext),
//               sk is the private key,
//               ss is the shared secret
int crypto_kem_dec(OUT unsigned char      *ss,
                   IN const unsigned char *ct,
                   IN const unsigned char *sk,
                   IN uint32_t            *error_count,
                   IN uint32_t            *right_count,
                   IN const pad_e_t       *R_e,
                   IN unsigned char       *fake_sk);
