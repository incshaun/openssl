/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/* Shamelessly copied from BoringSSL and converted to C. */

/* Test first part of SSL server handshake. */

#include <time.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include "fuzzer.h"

#include "rand.inc"

static const uint8_t kCertificateDER[] = {
    0x30, 0x82, 0x02, 0xff, 0x30, 0x82, 0x01, 0xe7, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x11, 0x00, 0xb1, 0x84, 0xee, 0x34, 0x99, 0x98, 0x76, 0xfb,
    0x6f, 0xb2, 0x15, 0xc8, 0x47, 0x79, 0x05, 0x9b, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30,
    0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x07,
    0x41, 0x63, 0x6d, 0x65, 0x20, 0x43, 0x6f, 0x30, 0x1e, 0x17, 0x0d, 0x31,
    0x35, 0x31, 0x31, 0x30, 0x37, 0x30, 0x30, 0x32, 0x34, 0x35, 0x36, 0x5a,
    0x17, 0x0d, 0x31, 0x36, 0x31, 0x31, 0x30, 0x36, 0x30, 0x30, 0x32, 0x34,
    0x35, 0x36, 0x5a, 0x30, 0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
    0x04, 0x0a, 0x13, 0x07, 0x41, 0x63, 0x6d, 0x65, 0x20, 0x43, 0x6f, 0x30,
    0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30,
    0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xce, 0x47, 0xcb, 0x11,
    0xbb, 0xd2, 0x9d, 0x8e, 0x9e, 0xd2, 0x1e, 0x14, 0xaf, 0xc7, 0xea, 0xb6,
    0xc9, 0x38, 0x2a, 0x6f, 0xb3, 0x7e, 0xfb, 0xbc, 0xfc, 0x59, 0x42, 0xb9,
    0x56, 0xf0, 0x4c, 0x3f, 0xf7, 0x31, 0x84, 0xbe, 0xac, 0x03, 0x9e, 0x71,
    0x91, 0x85, 0xd8, 0x32, 0xbd, 0x00, 0xea, 0xac, 0x65, 0xf6, 0x03, 0xc8,
    0x0f, 0x8b, 0xfd, 0x6e, 0x58, 0x88, 0x04, 0x41, 0x92, 0x74, 0xa6, 0x57,
    0x2e, 0x8e, 0x88, 0xd5, 0x3d, 0xda, 0x14, 0x3e, 0x63, 0x88, 0x22, 0xe3,
    0x53, 0xe9, 0xba, 0x39, 0x09, 0xac, 0xfb, 0xd0, 0x4c, 0xf2, 0x3c, 0x20,
    0xd6, 0x97, 0xe6, 0xed, 0xf1, 0x62, 0x1e, 0xe5, 0xc9, 0x48, 0xa0, 0xca,
    0x2e, 0x3c, 0x14, 0x5a, 0x82, 0xd4, 0xed, 0xb1, 0xe3, 0x43, 0xc1, 0x2a,
    0x59, 0xa5, 0xb9, 0xc8, 0x48, 0xa7, 0x39, 0x23, 0x74, 0xa7, 0x37, 0xb0,
    0x6f, 0xc3, 0x64, 0x99, 0x6c, 0xa2, 0x82, 0xc8, 0xf6, 0xdb, 0x86, 0x40,
    0xce, 0xd1, 0x85, 0x9f, 0xce, 0x69, 0xf4, 0x15, 0x2a, 0x23, 0xca, 0xea,
    0xb7, 0x7b, 0xdf, 0xfb, 0x43, 0x5f, 0xff, 0x7a, 0x49, 0x49, 0x0e, 0xe7,
    0x02, 0x51, 0x45, 0x13, 0xe8, 0x90, 0x64, 0x21, 0x0c, 0x26, 0x2b, 0x5d,
    0xfc, 0xe4, 0xb5, 0x86, 0x89, 0x43, 0x22, 0x4c, 0xf3, 0x3b, 0xf3, 0x09,
    0xc4, 0xa4, 0x10, 0x80, 0xf2, 0x46, 0xe2, 0x46, 0x8f, 0x76, 0x50, 0xbf,
    0xaf, 0x2b, 0x90, 0x1b, 0x78, 0xc7, 0xcf, 0xc1, 0x77, 0xd0, 0xfb, 0xa9,
    0xfb, 0xc9, 0x66, 0x5a, 0xc5, 0x9b, 0x31, 0x41, 0x67, 0x01, 0xbe, 0x33,
    0x10, 0xba, 0x05, 0x58, 0xed, 0x76, 0x53, 0xde, 0x5d, 0xc1, 0xe8, 0xbb,
    0x9f, 0xf1, 0xcd, 0xfb, 0xdf, 0x64, 0x7f, 0xd7, 0x18, 0xab, 0x0f, 0x94,
    0x28, 0x95, 0x4a, 0xcc, 0x6a, 0xa9, 0x50, 0xc7, 0x05, 0x47, 0x10, 0x41,
    0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x0e, 0x06,
    0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05,
    0xa0, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a,
    0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30, 0x0c,
    0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00,
    0x30, 0x19, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x12, 0x30, 0x10, 0x82,
    0x0e, 0x66, 0x75, 0x7a, 0x7a, 0x2e, 0x62, 0x6f, 0x72, 0x69, 0x6e, 0x67,
    0x73, 0x73, 0x6c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x92,
    0xde, 0xef, 0x96, 0x06, 0x7b, 0xff, 0x71, 0x7d, 0x4e, 0xa0, 0x7d, 0xae,
    0xb8, 0x22, 0xb4, 0x2c, 0xf7, 0x96, 0x9c, 0x37, 0x1d, 0x8f, 0xe7, 0xd9,
    0x47, 0xff, 0x3f, 0xe9, 0x35, 0x95, 0x0e, 0xdd, 0xdc, 0x7f, 0xc8, 0x8a,
    0x1e, 0x36, 0x1d, 0x38, 0x47, 0xfc, 0x76, 0xd2, 0x1f, 0x98, 0xa1, 0x36,
    0xac, 0xc8, 0x70, 0x38, 0x0a, 0x3d, 0x51, 0x8d, 0x0f, 0x03, 0x1b, 0xef,
    0x62, 0xa1, 0xcb, 0x2b, 0x4a, 0x8c, 0x12, 0x2b, 0x54, 0x50, 0x9a, 0x6b,
    0xfe, 0xaf, 0xd9, 0xf6, 0xbf, 0x58, 0x11, 0x58, 0x5e, 0xe5, 0x86, 0x1e,
    0x3b, 0x6b, 0x30, 0x7e, 0x72, 0x89, 0xe8, 0x6b, 0x7b, 0xb7, 0xaf, 0xef,
    0x8b, 0xa9, 0x3e, 0xb0, 0xcd, 0x0b, 0xef, 0xb0, 0x0c, 0x96, 0x2b, 0xc5,
    0x3b, 0xd5, 0xf1, 0xc2, 0xae, 0x3a, 0x60, 0xd9, 0x0f, 0x75, 0x37, 0x55,
    0x4d, 0x62, 0xd2, 0xed, 0x96, 0xac, 0x30, 0x6b, 0xda, 0xa1, 0x48, 0x17,
    0x96, 0x23, 0x85, 0x9a, 0x57, 0x77, 0xe9, 0x22, 0xa2, 0x37, 0x03, 0xba,
    0x49, 0x77, 0x40, 0x3b, 0x76, 0x4b, 0xda, 0xc1, 0x04, 0x57, 0x55, 0x34,
    0x22, 0x83, 0x45, 0x29, 0xab, 0x2e, 0x11, 0xff, 0x0d, 0xab, 0x55, 0xb1,
    0xa7, 0x58, 0x59, 0x05, 0x25, 0xf9, 0x1e, 0x3d, 0xb7, 0xac, 0x04, 0x39,
    0x2c, 0xf9, 0xaf, 0xb8, 0x68, 0xfb, 0x8e, 0x35, 0x71, 0x32, 0xff, 0x70,
    0xe9, 0x46, 0x6d, 0x5c, 0x06, 0x90, 0x88, 0x23, 0x48, 0x0c, 0x50, 0xeb,
    0x0a, 0xa9, 0xae, 0xe8, 0xfc, 0xbe, 0xa5, 0x76, 0x94, 0xd7, 0x64, 0x22,
    0x38, 0x98, 0x17, 0xa4, 0x3a, 0xa7, 0x59, 0x9f, 0x1d, 0x3b, 0x75, 0x90,
    0x1a, 0x81, 0xef, 0x19, 0xfb, 0x2b, 0xb7, 0xa7, 0x64, 0x61, 0x22, 0xa4,
    0x6f, 0x7b, 0xfa, 0x58, 0xbb, 0x8c, 0x4e, 0x77, 0x67, 0xd0, 0x5d, 0x58,
    0x76, 0x8a, 0xbb,
};

static const uint8_t kRSAPrivateKeyDER[] = {
    0x30, 0x82, 0x04, 0xa5, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
    0xce, 0x47, 0xcb, 0x11, 0xbb, 0xd2, 0x9d, 0x8e, 0x9e, 0xd2, 0x1e, 0x14,
    0xaf, 0xc7, 0xea, 0xb6, 0xc9, 0x38, 0x2a, 0x6f, 0xb3, 0x7e, 0xfb, 0xbc,
    0xfc, 0x59, 0x42, 0xb9, 0x56, 0xf0, 0x4c, 0x3f, 0xf7, 0x31, 0x84, 0xbe,
    0xac, 0x03, 0x9e, 0x71, 0x91, 0x85, 0xd8, 0x32, 0xbd, 0x00, 0xea, 0xac,
    0x65, 0xf6, 0x03, 0xc8, 0x0f, 0x8b, 0xfd, 0x6e, 0x58, 0x88, 0x04, 0x41,
    0x92, 0x74, 0xa6, 0x57, 0x2e, 0x8e, 0x88, 0xd5, 0x3d, 0xda, 0x14, 0x3e,
    0x63, 0x88, 0x22, 0xe3, 0x53, 0xe9, 0xba, 0x39, 0x09, 0xac, 0xfb, 0xd0,
    0x4c, 0xf2, 0x3c, 0x20, 0xd6, 0x97, 0xe6, 0xed, 0xf1, 0x62, 0x1e, 0xe5,
    0xc9, 0x48, 0xa0, 0xca, 0x2e, 0x3c, 0x14, 0x5a, 0x82, 0xd4, 0xed, 0xb1,
    0xe3, 0x43, 0xc1, 0x2a, 0x59, 0xa5, 0xb9, 0xc8, 0x48, 0xa7, 0x39, 0x23,
    0x74, 0xa7, 0x37, 0xb0, 0x6f, 0xc3, 0x64, 0x99, 0x6c, 0xa2, 0x82, 0xc8,
    0xf6, 0xdb, 0x86, 0x40, 0xce, 0xd1, 0x85, 0x9f, 0xce, 0x69, 0xf4, 0x15,
    0x2a, 0x23, 0xca, 0xea, 0xb7, 0x7b, 0xdf, 0xfb, 0x43, 0x5f, 0xff, 0x7a,
    0x49, 0x49, 0x0e, 0xe7, 0x02, 0x51, 0x45, 0x13, 0xe8, 0x90, 0x64, 0x21,
    0x0c, 0x26, 0x2b, 0x5d, 0xfc, 0xe4, 0xb5, 0x86, 0x89, 0x43, 0x22, 0x4c,
    0xf3, 0x3b, 0xf3, 0x09, 0xc4, 0xa4, 0x10, 0x80, 0xf2, 0x46, 0xe2, 0x46,
    0x8f, 0x76, 0x50, 0xbf, 0xaf, 0x2b, 0x90, 0x1b, 0x78, 0xc7, 0xcf, 0xc1,
    0x77, 0xd0, 0xfb, 0xa9, 0xfb, 0xc9, 0x66, 0x5a, 0xc5, 0x9b, 0x31, 0x41,
    0x67, 0x01, 0xbe, 0x33, 0x10, 0xba, 0x05, 0x58, 0xed, 0x76, 0x53, 0xde,
    0x5d, 0xc1, 0xe8, 0xbb, 0x9f, 0xf1, 0xcd, 0xfb, 0xdf, 0x64, 0x7f, 0xd7,
    0x18, 0xab, 0x0f, 0x94, 0x28, 0x95, 0x4a, 0xcc, 0x6a, 0xa9, 0x50, 0xc7,
    0x05, 0x47, 0x10, 0x41, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
    0x01, 0x00, 0xa8, 0x47, 0xb9, 0x4a, 0x06, 0x47, 0x93, 0x71, 0x3d, 0xef,
    0x7b, 0xca, 0xb4, 0x7c, 0x0a, 0xe6, 0x82, 0xd0, 0xe7, 0x0d, 0xa9, 0x08,
    0xf6, 0xa4, 0xfd, 0xd8, 0x73, 0xae, 0x6f, 0x56, 0x29, 0x5e, 0x25, 0x72,
    0xa8, 0x30, 0x44, 0x73, 0xcf, 0x56, 0x26, 0xb9, 0x61, 0xde, 0x42, 0x81,
    0xf4, 0xf0, 0x1f, 0x5d, 0xcb, 0x47, 0xf2, 0x26, 0xe9, 0xe0, 0x93, 0x28,
    0xa3, 0x10, 0x3b, 0x42, 0x1e, 0x51, 0x11, 0x12, 0x06, 0x5e, 0xaf, 0xce,
    0xb0, 0xa5, 0x14, 0xdd, 0x82, 0x58, 0xa1, 0xa4, 0x12, 0xdf, 0x65, 0x1d,
    0x51, 0x70, 0x64, 0xd5, 0x58, 0x68, 0x11, 0xa8, 0x6a, 0x23, 0xc2, 0xbf,
    0xa1, 0x25, 0x24, 0x47, 0xb3, 0xa4, 0x3c, 0x83, 0x96, 0xb7, 0x1f, 0xf4,
    0x44, 0xd4, 0xd1, 0xe9, 0xfc, 0x33, 0x68, 0x5e, 0xe2, 0x68, 0x99, 0x9c,
    0x91, 0xe8, 0x72, 0xc9, 0xd7, 0x8c, 0x80, 0x20, 0x8e, 0x77, 0x83, 0x4d,
    0xe4, 0xab, 0xf9, 0x74, 0xa1, 0xdf, 0xd3, 0xc0, 0x0d, 0x5b, 0x05, 0x51,
    0xc2, 0x6f, 0xb2, 0x91, 0x02, 0xec, 0xc0, 0x02, 0x1a, 0x5c, 0x91, 0x05,
    0xf1, 0xe3, 0xfa, 0x65, 0xc2, 0xad, 0x24, 0xe6, 0xe5, 0x3c, 0xb6, 0x16,
    0xf1, 0xa1, 0x67, 0x1a, 0x9d, 0x37, 0x56, 0xbf, 0x01, 0xd7, 0x3b, 0x35,
    0x30, 0x57, 0x73, 0xf4, 0xf0, 0x5e, 0xa7, 0xe8, 0x0a, 0xc1, 0x94, 0x17,
    0xcf, 0x0a, 0xbd, 0xf5, 0x31, 0xa7, 0x2d, 0xf7, 0xf5, 0xd9, 0x8c, 0xc2,
    0x01, 0xbd, 0xda, 0x16, 0x8e, 0xb9, 0x30, 0x40, 0xa6, 0x6e, 0xbd, 0xcd,
    0x4d, 0x84, 0x67, 0x4e, 0x0b, 0xce, 0xd5, 0xef, 0xf8, 0x08, 0x63, 0x02,
    0xc6, 0xc7, 0xf7, 0x67, 0x92, 0xe2, 0x23, 0x9d, 0x27, 0x22, 0x1d, 0xc6,
    0x67, 0x5e, 0x66, 0xbf, 0x03, 0xb8, 0xa9, 0x67, 0xd4, 0x39, 0xd8, 0x75,
    0xfa, 0xe8, 0xed, 0x56, 0xb8, 0x81, 0x02, 0x81, 0x81, 0x00, 0xf7, 0x46,
    0x68, 0xc6, 0x13, 0xf8, 0xba, 0x0f, 0x83, 0xdb, 0x05, 0xa8, 0x25, 0x00,
    0x70, 0x9c, 0x9e, 0x8b, 0x12, 0x34, 0x0d, 0x96, 0xcf, 0x0d, 0x98, 0x9b,
    0x8d, 0x9c, 0x96, 0x78, 0xd1, 0x3c, 0x01, 0x8c, 0xb9, 0x35, 0x5c, 0x20,
    0x42, 0xb4, 0x38, 0xe3, 0xd6, 0x54, 0xe7, 0x55, 0xd6, 0x26, 0x8a, 0x0c,
    0xf6, 0x1f, 0xe0, 0x04, 0xc1, 0x22, 0x42, 0x19, 0x61, 0xc4, 0x94, 0x7c,
    0x07, 0x2e, 0x80, 0x52, 0xfe, 0x8d, 0xe6, 0x92, 0x3a, 0x91, 0xfe, 0x72,
    0x99, 0xe1, 0x2a, 0x73, 0x76, 0xb1, 0x24, 0x20, 0x67, 0xde, 0x28, 0xcb,
    0x0e, 0xe6, 0x52, 0xb5, 0xfa, 0xfb, 0x8b, 0x1e, 0x6a, 0x1d, 0x09, 0x26,
    0xb9, 0xa7, 0x61, 0xba, 0xf8, 0x79, 0xd2, 0x66, 0x57, 0x28, 0xd7, 0x31,
    0xb5, 0x0b, 0x27, 0x19, 0x1e, 0x6f, 0x46, 0xfc, 0x54, 0x95, 0xeb, 0x78,
    0x01, 0xb6, 0xd9, 0x79, 0x5a, 0x4d, 0x02, 0x81, 0x81, 0x00, 0xd5, 0x8f,
    0x16, 0x53, 0x2f, 0x57, 0x93, 0xbf, 0x09, 0x75, 0xbf, 0x63, 0x40, 0x3d,
    0x27, 0xfd, 0x23, 0x21, 0xde, 0x9b, 0xe9, 0x73, 0x3f, 0x49, 0x02, 0xd2,
    0x38, 0x96, 0xcf, 0xc3, 0xba, 0x92, 0x07, 0x87, 0x52, 0xa9, 0x35, 0xe3,
    0x0c, 0xe4, 0x2f, 0x05, 0x7b, 0x37, 0xa5, 0x40, 0x9c, 0x3b, 0x94, 0xf7,
    0xad, 0xa0, 0xee, 0x3a, 0xa8, 0xfb, 0x1f, 0x11, 0x1f, 0xd8, 0x9a, 0x80,
    0x42, 0x3d, 0x7f, 0xa4, 0xb8, 0x9a, 0xaa, 0xea, 0x72, 0xc1, 0xe3, 0xed,
    0x06, 0x60, 0x92, 0x37, 0xf9, 0xba, 0xfb, 0x9e, 0xed, 0x05, 0xa6, 0xd4,
    0x72, 0x68, 0x4f, 0x63, 0xfe, 0xd6, 0x10, 0x0d, 0x4f, 0x0a, 0x93, 0xc6,
    0xb9, 0xd7, 0xaf, 0xfd, 0xd9, 0x57, 0x7d, 0xcb, 0x75, 0xe8, 0x93, 0x2b,
    0xae, 0x4f, 0xea, 0xd7, 0x30, 0x0b, 0x58, 0x44, 0x82, 0x0f, 0x84, 0x5d,
    0x62, 0x11, 0x78, 0xea, 0x5f, 0xc5, 0x02, 0x81, 0x81, 0x00, 0x82, 0x0c,
    0xc1, 0xe6, 0x0b, 0x72, 0xf1, 0x48, 0x5f, 0xac, 0xbd, 0x98, 0xe5, 0x7d,
    0x09, 0xbd, 0x15, 0x95, 0x47, 0x09, 0xa1, 0x6c, 0x03, 0x91, 0xbf, 0x05,
    0x70, 0xc1, 0x3e, 0x52, 0x64, 0x99, 0x0e, 0xa7, 0x98, 0x70, 0xfb, 0xf6,
    0xeb, 0x9e, 0x25, 0x9d, 0x8e, 0x88, 0x30, 0xf2, 0xf0, 0x22, 0x6c, 0xd0,
    0xcc, 0x51, 0x8f, 0x5c, 0x70, 0xc7, 0x37, 0xc4, 0x69, 0xab, 0x1d, 0xfc,
    0xed, 0x3a, 0x03, 0xbb, 0xa2, 0xad, 0xb6, 0xea, 0x89, 0x6b, 0x67, 0x4b,
    0x96, 0xaa, 0xd9, 0xcc, 0xc8, 0x4b, 0xfa, 0x18, 0x21, 0x08, 0xb2, 0xa3,
    0xb9, 0x3e, 0x61, 0x99, 0xdc, 0x5a, 0x97, 0x9c, 0x73, 0x6a, 0xb9, 0xf9,
    0x68, 0x03, 0x24, 0x5f, 0x55, 0x77, 0x9c, 0xb4, 0xbe, 0x7a, 0x78, 0x53,
    0x68, 0x48, 0x69, 0x53, 0xc8, 0xb1, 0xf5, 0xbf, 0x98, 0x2d, 0x11, 0x1e,
    0x98, 0xa8, 0x36, 0x50, 0xa0, 0xb1, 0x02, 0x81, 0x81, 0x00, 0x90, 0x88,
    0x30, 0x71, 0xc7, 0xfe, 0x9b, 0x6d, 0x95, 0x37, 0x6d, 0x79, 0xfc, 0x85,
    0xe7, 0x44, 0x78, 0xbc, 0x79, 0x6e, 0x47, 0x86, 0xc9, 0xf3, 0xdd, 0xc6,
    0xec, 0xa9, 0x94, 0x9f, 0x40, 0xeb, 0x87, 0xd0, 0xdb, 0xee, 0xcd, 0x1b,
    0x87, 0x23, 0xff, 0x76, 0xd4, 0x37, 0x8a, 0xcd, 0xb9, 0x6e, 0xd1, 0x98,
    0xf6, 0x97, 0x8d, 0xe3, 0x81, 0x6d, 0xc3, 0x4e, 0xd1, 0xa0, 0xc4, 0x9f,
    0xbd, 0x34, 0xe5, 0xe8, 0x53, 0x4f, 0xca, 0x10, 0xb5, 0xed, 0xe7, 0x16,
    0x09, 0x54, 0xde, 0x60, 0xa7, 0xd1, 0x16, 0x6e, 0x2e, 0xb7, 0xbe, 0x7a,
    0xd5, 0x9b, 0x26, 0xef, 0xe4, 0x0e, 0x77, 0xfa, 0xa9, 0xdd, 0xdc, 0xb9,
    0x88, 0x19, 0x23, 0x70, 0xc7, 0xe1, 0x60, 0xaf, 0x8c, 0x73, 0x04, 0xf7,
    0x71, 0x17, 0x81, 0x36, 0x75, 0xbb, 0x97, 0xd7, 0x75, 0xb6, 0x8e, 0xbc,
    0xac, 0x9c, 0x6a, 0x9b, 0x24, 0x89, 0x02, 0x81, 0x80, 0x5a, 0x2b, 0xc7,
    0x6b, 0x8c, 0x65, 0xdb, 0x04, 0x73, 0xab, 0x25, 0xe1, 0x5b, 0xbc, 0x3c,
    0xcf, 0x5a, 0x3c, 0x04, 0xae, 0x97, 0x2e, 0xfd, 0xa4, 0x97, 0x1f, 0x05,
    0x17, 0x27, 0xac, 0x7c, 0x30, 0x85, 0xb4, 0x82, 0x3f, 0x5b, 0xb7, 0x94,
    0x3b, 0x7f, 0x6c, 0x0c, 0xc7, 0x16, 0xc6, 0xa0, 0xbd, 0x80, 0xb0, 0x81,
    0xde, 0xa0, 0x23, 0xa6, 0xf6, 0x75, 0x33, 0x51, 0x35, 0xa2, 0x75, 0x55,
    0x70, 0x4d, 0x42, 0xbb, 0xcf, 0x54, 0xe4, 0xdb, 0x2d, 0x88, 0xa0, 0x7a,
    0xf2, 0x17, 0xa7, 0xdd, 0x13, 0x44, 0x9f, 0x5f, 0x6b, 0x2c, 0x42, 0x42,
    0x8b, 0x13, 0x4d, 0xf9, 0x5b, 0xf8, 0x33, 0x42, 0xd9, 0x9e, 0x50, 0x1c,
    0x7c, 0xbc, 0xfa, 0x62, 0x85, 0x0b, 0xcf, 0x99, 0xda, 0x9e, 0x04, 0x90,
    0xb2, 0xc6, 0xb2, 0x0a, 0x2a, 0x7c, 0x6d, 0x6a, 0x40, 0xfc, 0xf5, 0x50,
    0x98, 0x46, 0x89, 0x82, 0x40,
};


#ifndef OPENSSL_NO_EC
/*
 *  -----BEGIN EC PRIVATE KEY-----
 *  MHcCAQEEIJLyl7hJjpQL/RhP1x2zS79xdiPJQB683gWeqcqHPeZkoAoGCCqGSM49
 *  AwEHoUQDQgAEdsjygVYjjaKBF4CNECVllNf017p5/MxNSWDoTHy9I2GeDwEDDazI
 *  D/xy8JiYjtPKVE/Zqwbmivp2UwtH28a7NQ==
 *  -----END EC PRIVATE KEY-----
 */
static const char ECDSAPrivateKeyPEM[] = {
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x45,
    0x43, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45,
    0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x48, 0x63, 0x43, 0x41,
    0x51, 0x45, 0x45, 0x49, 0x4a, 0x4c, 0x79, 0x6c, 0x37, 0x68, 0x4a, 0x6a,
    0x70, 0x51, 0x4c, 0x2f, 0x52, 0x68, 0x50, 0x31, 0x78, 0x32, 0x7a, 0x53,
    0x37, 0x39, 0x78, 0x64, 0x69, 0x50, 0x4a, 0x51, 0x42, 0x36, 0x38, 0x33,
    0x67, 0x57, 0x65, 0x71, 0x63, 0x71, 0x48, 0x50, 0x65, 0x5a, 0x6b, 0x6f,
    0x41, 0x6f, 0x47, 0x43, 0x43, 0x71, 0x47, 0x53, 0x4d, 0x34, 0x39, 0x0a,
    0x41, 0x77, 0x45, 0x48, 0x6f, 0x55, 0x51, 0x44, 0x51, 0x67, 0x41, 0x45,
    0x64, 0x73, 0x6a, 0x79, 0x67, 0x56, 0x59, 0x6a, 0x6a, 0x61, 0x4b, 0x42,
    0x46, 0x34, 0x43, 0x4e, 0x45, 0x43, 0x56, 0x6c, 0x6c, 0x4e, 0x66, 0x30,
    0x31, 0x37, 0x70, 0x35, 0x2f, 0x4d, 0x78, 0x4e, 0x53, 0x57, 0x44, 0x6f,
    0x54, 0x48, 0x79, 0x39, 0x49, 0x32, 0x47, 0x65, 0x44, 0x77, 0x45, 0x44,
    0x44, 0x61, 0x7a, 0x49, 0x0a, 0x44, 0x2f, 0x78, 0x79, 0x38, 0x4a, 0x69,
    0x59, 0x6a, 0x74, 0x50, 0x4b, 0x56, 0x45, 0x2f, 0x5a, 0x71, 0x77, 0x62,
    0x6d, 0x69, 0x76, 0x70, 0x32, 0x55, 0x77, 0x74, 0x48, 0x32, 0x38, 0x61,
    0x37, 0x4e, 0x51, 0x3d, 0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45,
    0x4e, 0x44, 0x20, 0x45, 0x43, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54,
    0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a
};

/*
 * -----BEGIN CERTIFICATE-----
 *  MIIBXzCCAQagAwIBAgIJAK6/Yvf/ain6MAoGCCqGSM49BAMCMBIxEDAOBgNVBAoM
 *  B0FjbWUgQ28wHhcNMTYxMjI1MTEzOTI3WhcNMjYxMjI1MTEzOTI3WjASMRAwDgYD
 *  VQQKDAdBY21lIENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdsjygVYjjaKB
 *  F4CNECVllNf017p5/MxNSWDoTHy9I2GeDwEDDazID/xy8JiYjtPKVE/Zqwbmivp2
 *  UwtH28a7NaNFMEMwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAwEwYDVR0lBAwwCgYI
 *  KwYBBQUHAwEwFAYDVR0RBA0wC4IJbG9jYWxob3N0MAoGCCqGSM49BAMCA0cAMEQC
 *  IEzr3t/jejVE9oSnBp8c3P2p+lDLVRrB8zxLyjZvirUXAiAyQPaE9MNcL8/nRpuu
 *  99I1enCSmWIAJ57IwuJ/n1d45Q==
 *  -----END CERTIFICATE-----
 */
static const char ECDSACertPEM[] = {
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x43,
    0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d,
    0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x42, 0x58, 0x7a, 0x43, 0x43,
    0x41, 0x51, 0x61, 0x67, 0x41, 0x77, 0x49, 0x42, 0x41, 0x67, 0x49, 0x4a,
    0x41, 0x4b, 0x36, 0x2f, 0x59, 0x76, 0x66, 0x2f, 0x61, 0x69, 0x6e, 0x36,
    0x4d, 0x41, 0x6f, 0x47, 0x43, 0x43, 0x71, 0x47, 0x53, 0x4d, 0x34, 0x39,
    0x42, 0x41, 0x4d, 0x43, 0x4d, 0x42, 0x49, 0x78, 0x45, 0x44, 0x41, 0x4f,
    0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x6f, 0x4d, 0x0a, 0x42, 0x30, 0x46,
    0x6a, 0x62, 0x57, 0x55, 0x67, 0x51, 0x32, 0x38, 0x77, 0x48, 0x68, 0x63,
    0x4e, 0x4d, 0x54, 0x59, 0x78, 0x4d, 0x6a, 0x49, 0x31, 0x4d, 0x54, 0x45,
    0x7a, 0x4f, 0x54, 0x49, 0x33, 0x57, 0x68, 0x63, 0x4e, 0x4d, 0x6a, 0x59,
    0x78, 0x4d, 0x6a, 0x49, 0x31, 0x4d, 0x54, 0x45, 0x7a, 0x4f, 0x54, 0x49,
    0x33, 0x57, 0x6a, 0x41, 0x53, 0x4d, 0x52, 0x41, 0x77, 0x44, 0x67, 0x59,
    0x44, 0x0a, 0x56, 0x51, 0x51, 0x4b, 0x44, 0x41, 0x64, 0x42, 0x59, 0x32,
    0x31, 0x6c, 0x49, 0x45, 0x4e, 0x76, 0x4d, 0x46, 0x6b, 0x77, 0x45, 0x77,
    0x59, 0x48, 0x4b, 0x6f, 0x5a, 0x49, 0x7a, 0x6a, 0x30, 0x43, 0x41, 0x51,
    0x59, 0x49, 0x4b, 0x6f, 0x5a, 0x49, 0x7a, 0x6a, 0x30, 0x44, 0x41, 0x51,
    0x63, 0x44, 0x51, 0x67, 0x41, 0x45, 0x64, 0x73, 0x6a, 0x79, 0x67, 0x56,
    0x59, 0x6a, 0x6a, 0x61, 0x4b, 0x42, 0x0a, 0x46, 0x34, 0x43, 0x4e, 0x45,
    0x43, 0x56, 0x6c, 0x6c, 0x4e, 0x66, 0x30, 0x31, 0x37, 0x70, 0x35, 0x2f,
    0x4d, 0x78, 0x4e, 0x53, 0x57, 0x44, 0x6f, 0x54, 0x48, 0x79, 0x39, 0x49,
    0x32, 0x47, 0x65, 0x44, 0x77, 0x45, 0x44, 0x44, 0x61, 0x7a, 0x49, 0x44,
    0x2f, 0x78, 0x79, 0x38, 0x4a, 0x69, 0x59, 0x6a, 0x74, 0x50, 0x4b, 0x56,
    0x45, 0x2f, 0x5a, 0x71, 0x77, 0x62, 0x6d, 0x69, 0x76, 0x70, 0x32, 0x0a,
    0x55, 0x77, 0x74, 0x48, 0x32, 0x38, 0x61, 0x37, 0x4e, 0x61, 0x4e, 0x46,
    0x4d, 0x45, 0x4d, 0x77, 0x43, 0x51, 0x59, 0x44, 0x56, 0x52, 0x30, 0x54,
    0x42, 0x41, 0x49, 0x77, 0x41, 0x44, 0x41, 0x4c, 0x42, 0x67, 0x4e, 0x56,
    0x48, 0x51, 0x38, 0x45, 0x42, 0x41, 0x4d, 0x43, 0x42, 0x61, 0x41, 0x77,
    0x45, 0x77, 0x59, 0x44, 0x56, 0x52, 0x30, 0x6c, 0x42, 0x41, 0x77, 0x77,
    0x43, 0x67, 0x59, 0x49, 0x0a, 0x4b, 0x77, 0x59, 0x42, 0x42, 0x51, 0x55,
    0x48, 0x41, 0x77, 0x45, 0x77, 0x46, 0x41, 0x59, 0x44, 0x56, 0x52, 0x30,
    0x52, 0x42, 0x41, 0x30, 0x77, 0x43, 0x34, 0x49, 0x4a, 0x62, 0x47, 0x39,
    0x6a, 0x59, 0x57, 0x78, 0x6f, 0x62, 0x33, 0x4e, 0x30, 0x4d, 0x41, 0x6f,
    0x47, 0x43, 0x43, 0x71, 0x47, 0x53, 0x4d, 0x34, 0x39, 0x42, 0x41, 0x4d,
    0x43, 0x41, 0x30, 0x63, 0x41, 0x4d, 0x45, 0x51, 0x43, 0x0a, 0x49, 0x45,
    0x7a, 0x72, 0x33, 0x74, 0x2f, 0x6a, 0x65, 0x6a, 0x56, 0x45, 0x39, 0x6f,
    0x53, 0x6e, 0x42, 0x70, 0x38, 0x63, 0x33, 0x50, 0x32, 0x70, 0x2b, 0x6c,
    0x44, 0x4c, 0x56, 0x52, 0x72, 0x42, 0x38, 0x7a, 0x78, 0x4c, 0x79, 0x6a,
    0x5a, 0x76, 0x69, 0x72, 0x55, 0x58, 0x41, 0x69, 0x41, 0x79, 0x51, 0x50,
    0x61, 0x45, 0x39, 0x4d, 0x4e, 0x63, 0x4c, 0x38, 0x2f, 0x6e, 0x52, 0x70,
    0x75, 0x75, 0x0a, 0x39, 0x39, 0x49, 0x31, 0x65, 0x6e, 0x43, 0x53, 0x6d,
    0x57, 0x49, 0x41, 0x4a, 0x35, 0x37, 0x49, 0x77, 0x75, 0x4a, 0x2f, 0x6e,
    0x31, 0x64, 0x34, 0x35, 0x51, 0x3d, 0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d,
    0x2d, 0x45, 0x4e, 0x44, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46, 0x49,
    0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a
};
#endif

#ifndef OPENSSL_NO_DSA
/*
 * -----BEGIN DSA PRIVATE KEY-----
 * MIIBuwIBAAKBgQDdkFKzNABLOha7Eqj7004+p5fhtR6bxpujToMmSZTYi8igVVXP
 * Wzf03ULKS5UKjA6WpR6EiZAhm+PdxusZ5xfAuRZLdKy0bgxn1f348Rwh+EQNaEM8
 * 0TGcnw5ijwKmSw5yyHPDWdiHzoqEBlhAf8Nl22YTXax/clsc/pu/RRLAdwIVAIEg
 * QqWRf/1EIZZcgM65Qpd65YuxAoGBAKBauV/RuloFHoSy5iWXESDywiS380tN5974
 * GukGwoYdZo5uSIH6ahpeNSef0MbHGAzr7ZVEnhCQfRAwH1gRvSHoq/Rbmcvtd3r+
 * QtQHOwvQHgLAynhI4i73c794czHaR+439bmcaSwDnQduRM85Mho/jiiZzAVPxBmG
 * POIMWNXXAoGAI6Ep5IE7yn3JzkXO9B6tC3bbDM+ZzuuInwZLbtZ8lim7Dsqabg4k
 * 2YbE4R95Bnfwnjsyl80mq/DbQN5lAHBvjDrkC6ItojBGKI3+iIrqGUEJdxvl4ulj
 * F0PmSD7zvIG8BfocKOel+EHH0YryExiW6krV1KW2ZRmJrqSFw6KCjV0CFFQFbPfU
 * xy5PmKytJmXR8BmppkIO
 * -----END DSA PRIVATE KEY-----
 */
static const char DSAPrivateKeyPEM[] = {
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x44,
    0x53, 0x41, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b,
    0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x42,
    0x75, 0x77, 0x49, 0x42, 0x41, 0x41, 0x4b, 0x42, 0x67, 0x51, 0x44, 0x64,
    0x6b, 0x46, 0x4b, 0x7a, 0x4e, 0x41, 0x42, 0x4c, 0x4f, 0x68, 0x61, 0x37,
    0x45, 0x71, 0x6a, 0x37, 0x30, 0x30, 0x34, 0x2b, 0x70, 0x35, 0x66, 0x68,
    0x74, 0x52, 0x36, 0x62, 0x78, 0x70, 0x75, 0x6a, 0x54, 0x6f, 0x4d, 0x6d,
    0x53, 0x5a, 0x54, 0x59, 0x69, 0x38, 0x69, 0x67, 0x56, 0x56, 0x58, 0x50,
    0x0a, 0x57, 0x7a, 0x66, 0x30, 0x33, 0x55, 0x4c, 0x4b, 0x53, 0x35, 0x55,
    0x4b, 0x6a, 0x41, 0x36, 0x57, 0x70, 0x52, 0x36, 0x45, 0x69, 0x5a, 0x41,
    0x68, 0x6d, 0x2b, 0x50, 0x64, 0x78, 0x75, 0x73, 0x5a, 0x35, 0x78, 0x66,
    0x41, 0x75, 0x52, 0x5a, 0x4c, 0x64, 0x4b, 0x79, 0x30, 0x62, 0x67, 0x78,
    0x6e, 0x31, 0x66, 0x33, 0x34, 0x38, 0x52, 0x77, 0x68, 0x2b, 0x45, 0x51,
    0x4e, 0x61, 0x45, 0x4d, 0x38, 0x0a, 0x30, 0x54, 0x47, 0x63, 0x6e, 0x77,
    0x35, 0x69, 0x6a, 0x77, 0x4b, 0x6d, 0x53, 0x77, 0x35, 0x79, 0x79, 0x48,
    0x50, 0x44, 0x57, 0x64, 0x69, 0x48, 0x7a, 0x6f, 0x71, 0x45, 0x42, 0x6c,
    0x68, 0x41, 0x66, 0x38, 0x4e, 0x6c, 0x32, 0x32, 0x59, 0x54, 0x58, 0x61,
    0x78, 0x2f, 0x63, 0x6c, 0x73, 0x63, 0x2f, 0x70, 0x75, 0x2f, 0x52, 0x52,
    0x4c, 0x41, 0x64, 0x77, 0x49, 0x56, 0x41, 0x49, 0x45, 0x67, 0x0a, 0x51,
    0x71, 0x57, 0x52, 0x66, 0x2f, 0x31, 0x45, 0x49, 0x5a, 0x5a, 0x63, 0x67,
    0x4d, 0x36, 0x35, 0x51, 0x70, 0x64, 0x36, 0x35, 0x59, 0x75, 0x78, 0x41,
    0x6f, 0x47, 0x42, 0x41, 0x4b, 0x42, 0x61, 0x75, 0x56, 0x2f, 0x52, 0x75,
    0x6c, 0x6f, 0x46, 0x48, 0x6f, 0x53, 0x79, 0x35, 0x69, 0x57, 0x58, 0x45,
    0x53, 0x44, 0x79, 0x77, 0x69, 0x53, 0x33, 0x38, 0x30, 0x74, 0x4e, 0x35,
    0x39, 0x37, 0x34, 0x0a, 0x47, 0x75, 0x6b, 0x47, 0x77, 0x6f, 0x59, 0x64,
    0x5a, 0x6f, 0x35, 0x75, 0x53, 0x49, 0x48, 0x36, 0x61, 0x68, 0x70, 0x65,
    0x4e, 0x53, 0x65, 0x66, 0x30, 0x4d, 0x62, 0x48, 0x47, 0x41, 0x7a, 0x72,
    0x37, 0x5a, 0x56, 0x45, 0x6e, 0x68, 0x43, 0x51, 0x66, 0x52, 0x41, 0x77,
    0x48, 0x31, 0x67, 0x52, 0x76, 0x53, 0x48, 0x6f, 0x71, 0x2f, 0x52, 0x62,
    0x6d, 0x63, 0x76, 0x74, 0x64, 0x33, 0x72, 0x2b, 0x0a, 0x51, 0x74, 0x51,
    0x48, 0x4f, 0x77, 0x76, 0x51, 0x48, 0x67, 0x4c, 0x41, 0x79, 0x6e, 0x68,
    0x49, 0x34, 0x69, 0x37, 0x33, 0x63, 0x37, 0x39, 0x34, 0x63, 0x7a, 0x48,
    0x61, 0x52, 0x2b, 0x34, 0x33, 0x39, 0x62, 0x6d, 0x63, 0x61, 0x53, 0x77,
    0x44, 0x6e, 0x51, 0x64, 0x75, 0x52, 0x4d, 0x38, 0x35, 0x4d, 0x68, 0x6f,
    0x2f, 0x6a, 0x69, 0x69, 0x5a, 0x7a, 0x41, 0x56, 0x50, 0x78, 0x42, 0x6d,
    0x47, 0x0a, 0x50, 0x4f, 0x49, 0x4d, 0x57, 0x4e, 0x58, 0x58, 0x41, 0x6f,
    0x47, 0x41, 0x49, 0x36, 0x45, 0x70, 0x35, 0x49, 0x45, 0x37, 0x79, 0x6e,
    0x33, 0x4a, 0x7a, 0x6b, 0x58, 0x4f, 0x39, 0x42, 0x36, 0x74, 0x43, 0x33,
    0x62, 0x62, 0x44, 0x4d, 0x2b, 0x5a, 0x7a, 0x75, 0x75, 0x49, 0x6e, 0x77,
    0x5a, 0x4c, 0x62, 0x74, 0x5a, 0x38, 0x6c, 0x69, 0x6d, 0x37, 0x44, 0x73,
    0x71, 0x61, 0x62, 0x67, 0x34, 0x6b, 0x0a, 0x32, 0x59, 0x62, 0x45, 0x34,
    0x52, 0x39, 0x35, 0x42, 0x6e, 0x66, 0x77, 0x6e, 0x6a, 0x73, 0x79, 0x6c,
    0x38, 0x30, 0x6d, 0x71, 0x2f, 0x44, 0x62, 0x51, 0x4e, 0x35, 0x6c, 0x41,
    0x48, 0x42, 0x76, 0x6a, 0x44, 0x72, 0x6b, 0x43, 0x36, 0x49, 0x74, 0x6f,
    0x6a, 0x42, 0x47, 0x4b, 0x49, 0x33, 0x2b, 0x69, 0x49, 0x72, 0x71, 0x47,
    0x55, 0x45, 0x4a, 0x64, 0x78, 0x76, 0x6c, 0x34, 0x75, 0x6c, 0x6a, 0x0a,
    0x46, 0x30, 0x50, 0x6d, 0x53, 0x44, 0x37, 0x7a, 0x76, 0x49, 0x47, 0x38,
    0x42, 0x66, 0x6f, 0x63, 0x4b, 0x4f, 0x65, 0x6c, 0x2b, 0x45, 0x48, 0x48,
    0x30, 0x59, 0x72, 0x79, 0x45, 0x78, 0x69, 0x57, 0x36, 0x6b, 0x72, 0x56,
    0x31, 0x4b, 0x57, 0x32, 0x5a, 0x52, 0x6d, 0x4a, 0x72, 0x71, 0x53, 0x46,
    0x77, 0x36, 0x4b, 0x43, 0x6a, 0x56, 0x30, 0x43, 0x46, 0x46, 0x51, 0x46,
    0x62, 0x50, 0x66, 0x55, 0x0a, 0x78, 0x79, 0x35, 0x50, 0x6d, 0x4b, 0x79,
    0x74, 0x4a, 0x6d, 0x58, 0x52, 0x38, 0x42, 0x6d, 0x70, 0x70, 0x6b, 0x49,
    0x4f, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x44,
    0x53, 0x41, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b,
    0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a
};

/*
 * -----BEGIN CERTIFICATE-----
 * MIICqTCCAmegAwIBAgIJAILDGUk37fWGMAsGCWCGSAFlAwQDAjASMRAwDgYDVQQK
 * DAdBY21lIENvMB4XDTE2MTIyNTEzMjUzNloXDTI2MTIyNTEzMjUzNlowEjEQMA4G
 * A1UECgwHQWNtZSBDbzCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQDdkFKzNABLOha7
 * Eqj7004+p5fhtR6bxpujToMmSZTYi8igVVXPWzf03ULKS5UKjA6WpR6EiZAhm+Pd
 * xusZ5xfAuRZLdKy0bgxn1f348Rwh+EQNaEM80TGcnw5ijwKmSw5yyHPDWdiHzoqE
 * BlhAf8Nl22YTXax/clsc/pu/RRLAdwIVAIEgQqWRf/1EIZZcgM65Qpd65YuxAoGB
 * AKBauV/RuloFHoSy5iWXESDywiS380tN5974GukGwoYdZo5uSIH6ahpeNSef0MbH
 * GAzr7ZVEnhCQfRAwH1gRvSHoq/Rbmcvtd3r+QtQHOwvQHgLAynhI4i73c794czHa
 * R+439bmcaSwDnQduRM85Mho/jiiZzAVPxBmGPOIMWNXXA4GEAAKBgCOhKeSBO8p9
 * yc5FzvQerQt22wzPmc7riJ8GS27WfJYpuw7Kmm4OJNmGxOEfeQZ38J47MpfNJqvw
 * 20DeZQBwb4w65AuiLaIwRiiN/oiK6hlBCXcb5eLpYxdD5kg+87yBvAX6HCjnpfhB
 * x9GK8hMYlupK1dSltmUZia6khcOigo1do0UwQzAJBgNVHRMEAjAAMAsGA1UdDwQE
 * AwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAUBgNVHREEDTALgglsb2NhbGhvc3Qw
 * CwYJYIZIAWUDBAMCAy8AMCwCFClxInXTRWNJEWdi5ilNr/fbM1bKAhQy4B7wtmfd
 * I+zV6g3w9qBkNqStpA==
 * -----END CERTIFICATE-----
 */
static const char DSACertPEM[] = {
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x43,
    0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d,
    0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x43, 0x71, 0x54, 0x43, 0x43,
    0x41, 0x6d, 0x65, 0x67, 0x41, 0x77, 0x49, 0x42, 0x41, 0x67, 0x49, 0x4a,
    0x41, 0x49, 0x4c, 0x44, 0x47, 0x55, 0x6b, 0x33, 0x37, 0x66, 0x57, 0x47,
    0x4d, 0x41, 0x73, 0x47, 0x43, 0x57, 0x43, 0x47, 0x53, 0x41, 0x46, 0x6c,
    0x41, 0x77, 0x51, 0x44, 0x41, 0x6a, 0x41, 0x53, 0x4d, 0x52, 0x41, 0x77,
    0x44, 0x67, 0x59, 0x44, 0x56, 0x51, 0x51, 0x4b, 0x0a, 0x44, 0x41, 0x64,
    0x42, 0x59, 0x32, 0x31, 0x6c, 0x49, 0x45, 0x4e, 0x76, 0x4d, 0x42, 0x34,
    0x58, 0x44, 0x54, 0x45, 0x32, 0x4d, 0x54, 0x49, 0x79, 0x4e, 0x54, 0x45,
    0x7a, 0x4d, 0x6a, 0x55, 0x7a, 0x4e, 0x6c, 0x6f, 0x58, 0x44, 0x54, 0x49,
    0x32, 0x4d, 0x54, 0x49, 0x79, 0x4e, 0x54, 0x45, 0x7a, 0x4d, 0x6a, 0x55,
    0x7a, 0x4e, 0x6c, 0x6f, 0x77, 0x45, 0x6a, 0x45, 0x51, 0x4d, 0x41, 0x34,
    0x47, 0x0a, 0x41, 0x31, 0x55, 0x45, 0x43, 0x67, 0x77, 0x48, 0x51, 0x57,
    0x4e, 0x74, 0x5a, 0x53, 0x42, 0x44, 0x62, 0x7a, 0x43, 0x43, 0x41, 0x62,
    0x63, 0x77, 0x67, 0x67, 0x45, 0x73, 0x42, 0x67, 0x63, 0x71, 0x68, 0x6b,
    0x6a, 0x4f, 0x4f, 0x41, 0x51, 0x42, 0x4d, 0x49, 0x49, 0x42, 0x48, 0x77,
    0x4b, 0x42, 0x67, 0x51, 0x44, 0x64, 0x6b, 0x46, 0x4b, 0x7a, 0x4e, 0x41,
    0x42, 0x4c, 0x4f, 0x68, 0x61, 0x37, 0x0a, 0x45, 0x71, 0x6a, 0x37, 0x30,
    0x30, 0x34, 0x2b, 0x70, 0x35, 0x66, 0x68, 0x74, 0x52, 0x36, 0x62, 0x78,
    0x70, 0x75, 0x6a, 0x54, 0x6f, 0x4d, 0x6d, 0x53, 0x5a, 0x54, 0x59, 0x69,
    0x38, 0x69, 0x67, 0x56, 0x56, 0x58, 0x50, 0x57, 0x7a, 0x66, 0x30, 0x33,
    0x55, 0x4c, 0x4b, 0x53, 0x35, 0x55, 0x4b, 0x6a, 0x41, 0x36, 0x57, 0x70,
    0x52, 0x36, 0x45, 0x69, 0x5a, 0x41, 0x68, 0x6d, 0x2b, 0x50, 0x64, 0x0a,
    0x78, 0x75, 0x73, 0x5a, 0x35, 0x78, 0x66, 0x41, 0x75, 0x52, 0x5a, 0x4c,
    0x64, 0x4b, 0x79, 0x30, 0x62, 0x67, 0x78, 0x6e, 0x31, 0x66, 0x33, 0x34,
    0x38, 0x52, 0x77, 0x68, 0x2b, 0x45, 0x51, 0x4e, 0x61, 0x45, 0x4d, 0x38,
    0x30, 0x54, 0x47, 0x63, 0x6e, 0x77, 0x35, 0x69, 0x6a, 0x77, 0x4b, 0x6d,
    0x53, 0x77, 0x35, 0x79, 0x79, 0x48, 0x50, 0x44, 0x57, 0x64, 0x69, 0x48,
    0x7a, 0x6f, 0x71, 0x45, 0x0a, 0x42, 0x6c, 0x68, 0x41, 0x66, 0x38, 0x4e,
    0x6c, 0x32, 0x32, 0x59, 0x54, 0x58, 0x61, 0x78, 0x2f, 0x63, 0x6c, 0x73,
    0x63, 0x2f, 0x70, 0x75, 0x2f, 0x52, 0x52, 0x4c, 0x41, 0x64, 0x77, 0x49,
    0x56, 0x41, 0x49, 0x45, 0x67, 0x51, 0x71, 0x57, 0x52, 0x66, 0x2f, 0x31,
    0x45, 0x49, 0x5a, 0x5a, 0x63, 0x67, 0x4d, 0x36, 0x35, 0x51, 0x70, 0x64,
    0x36, 0x35, 0x59, 0x75, 0x78, 0x41, 0x6f, 0x47, 0x42, 0x0a, 0x41, 0x4b,
    0x42, 0x61, 0x75, 0x56, 0x2f, 0x52, 0x75, 0x6c, 0x6f, 0x46, 0x48, 0x6f,
    0x53, 0x79, 0x35, 0x69, 0x57, 0x58, 0x45, 0x53, 0x44, 0x79, 0x77, 0x69,
    0x53, 0x33, 0x38, 0x30, 0x74, 0x4e, 0x35, 0x39, 0x37, 0x34, 0x47, 0x75,
    0x6b, 0x47, 0x77, 0x6f, 0x59, 0x64, 0x5a, 0x6f, 0x35, 0x75, 0x53, 0x49,
    0x48, 0x36, 0x61, 0x68, 0x70, 0x65, 0x4e, 0x53, 0x65, 0x66, 0x30, 0x4d,
    0x62, 0x48, 0x0a, 0x47, 0x41, 0x7a, 0x72, 0x37, 0x5a, 0x56, 0x45, 0x6e,
    0x68, 0x43, 0x51, 0x66, 0x52, 0x41, 0x77, 0x48, 0x31, 0x67, 0x52, 0x76,
    0x53, 0x48, 0x6f, 0x71, 0x2f, 0x52, 0x62, 0x6d, 0x63, 0x76, 0x74, 0x64,
    0x33, 0x72, 0x2b, 0x51, 0x74, 0x51, 0x48, 0x4f, 0x77, 0x76, 0x51, 0x48,
    0x67, 0x4c, 0x41, 0x79, 0x6e, 0x68, 0x49, 0x34, 0x69, 0x37, 0x33, 0x63,
    0x37, 0x39, 0x34, 0x63, 0x7a, 0x48, 0x61, 0x0a, 0x52, 0x2b, 0x34, 0x33,
    0x39, 0x62, 0x6d, 0x63, 0x61, 0x53, 0x77, 0x44, 0x6e, 0x51, 0x64, 0x75,
    0x52, 0x4d, 0x38, 0x35, 0x4d, 0x68, 0x6f, 0x2f, 0x6a, 0x69, 0x69, 0x5a,
    0x7a, 0x41, 0x56, 0x50, 0x78, 0x42, 0x6d, 0x47, 0x50, 0x4f, 0x49, 0x4d,
    0x57, 0x4e, 0x58, 0x58, 0x41, 0x34, 0x47, 0x45, 0x41, 0x41, 0x4b, 0x42,
    0x67, 0x43, 0x4f, 0x68, 0x4b, 0x65, 0x53, 0x42, 0x4f, 0x38, 0x70, 0x39,
    0x0a, 0x79, 0x63, 0x35, 0x46, 0x7a, 0x76, 0x51, 0x65, 0x72, 0x51, 0x74,
    0x32, 0x32, 0x77, 0x7a, 0x50, 0x6d, 0x63, 0x37, 0x72, 0x69, 0x4a, 0x38,
    0x47, 0x53, 0x32, 0x37, 0x57, 0x66, 0x4a, 0x59, 0x70, 0x75, 0x77, 0x37,
    0x4b, 0x6d, 0x6d, 0x34, 0x4f, 0x4a, 0x4e, 0x6d, 0x47, 0x78, 0x4f, 0x45,
    0x66, 0x65, 0x51, 0x5a, 0x33, 0x38, 0x4a, 0x34, 0x37, 0x4d, 0x70, 0x66,
    0x4e, 0x4a, 0x71, 0x76, 0x77, 0x0a, 0x32, 0x30, 0x44, 0x65, 0x5a, 0x51,
    0x42, 0x77, 0x62, 0x34, 0x77, 0x36, 0x35, 0x41, 0x75, 0x69, 0x4c, 0x61,
    0x49, 0x77, 0x52, 0x69, 0x69, 0x4e, 0x2f, 0x6f, 0x69, 0x4b, 0x36, 0x68,
    0x6c, 0x42, 0x43, 0x58, 0x63, 0x62, 0x35, 0x65, 0x4c, 0x70, 0x59, 0x78,
    0x64, 0x44, 0x35, 0x6b, 0x67, 0x2b, 0x38, 0x37, 0x79, 0x42, 0x76, 0x41,
    0x58, 0x36, 0x48, 0x43, 0x6a, 0x6e, 0x70, 0x66, 0x68, 0x42, 0x0a, 0x78,
    0x39, 0x47, 0x4b, 0x38, 0x68, 0x4d, 0x59, 0x6c, 0x75, 0x70, 0x4b, 0x31,
    0x64, 0x53, 0x6c, 0x74, 0x6d, 0x55, 0x5a, 0x69, 0x61, 0x36, 0x6b, 0x68,
    0x63, 0x4f, 0x69, 0x67, 0x6f, 0x31, 0x64, 0x6f, 0x30, 0x55, 0x77, 0x51,
    0x7a, 0x41, 0x4a, 0x42, 0x67, 0x4e, 0x56, 0x48, 0x52, 0x4d, 0x45, 0x41,
    0x6a, 0x41, 0x41, 0x4d, 0x41, 0x73, 0x47, 0x41, 0x31, 0x55, 0x64, 0x44,
    0x77, 0x51, 0x45, 0x0a, 0x41, 0x77, 0x49, 0x46, 0x6f, 0x44, 0x41, 0x54,
    0x42, 0x67, 0x4e, 0x56, 0x48, 0x53, 0x55, 0x45, 0x44, 0x44, 0x41, 0x4b,
    0x42, 0x67, 0x67, 0x72, 0x42, 0x67, 0x45, 0x46, 0x42, 0x51, 0x63, 0x44,
    0x41, 0x54, 0x41, 0x55, 0x42, 0x67, 0x4e, 0x56, 0x48, 0x52, 0x45, 0x45,
    0x44, 0x54, 0x41, 0x4c, 0x67, 0x67, 0x6c, 0x73, 0x62, 0x32, 0x4e, 0x68,
    0x62, 0x47, 0x68, 0x76, 0x63, 0x33, 0x51, 0x77, 0x0a, 0x43, 0x77, 0x59,
    0x4a, 0x59, 0x49, 0x5a, 0x49, 0x41, 0x57, 0x55, 0x44, 0x42, 0x41, 0x4d,
    0x43, 0x41, 0x79, 0x38, 0x41, 0x4d, 0x43, 0x77, 0x43, 0x46, 0x43, 0x6c,
    0x78, 0x49, 0x6e, 0x58, 0x54, 0x52, 0x57, 0x4e, 0x4a, 0x45, 0x57, 0x64,
    0x69, 0x35, 0x69, 0x6c, 0x4e, 0x72, 0x2f, 0x66, 0x62, 0x4d, 0x31, 0x62,
    0x4b, 0x41, 0x68, 0x51, 0x79, 0x34, 0x42, 0x37, 0x77, 0x74, 0x6d, 0x66,
    0x64, 0x0a, 0x49, 0x2b, 0x7a, 0x56, 0x36, 0x67, 0x33, 0x77, 0x39, 0x71,
    0x42, 0x6b, 0x4e, 0x71, 0x53, 0x74, 0x70, 0x41, 0x3d, 0x3d, 0x0a, 0x2d,
    0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x43, 0x45, 0x52, 0x54,
    0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
    0x0a
};
#endif

/* unused, to avoid warning. */
static int idx;

#define FUZZTIME 1485898104

#define TIME_IMPL(t) { if (t != NULL) *t = FUZZTIME; return FUZZTIME; }

/*
 * This might not work in all cases (and definitely not on Windows
 * because of the way linkers are) and callees can still get the
 * current time instead of the fixed time. This will just result
 * in things not being fully reproducible and have a slightly
 * different coverage.
 */
#if !defined(_WIN32)
time_t time(time_t *t) TIME_IMPL(t)
#endif

int FuzzerInitialize(int *argc, char ***argv)
{
    STACK_OF(SSL_COMP) *comp_methods;

    VR_OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ASYNC, NULL);
    VR_OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
    VR_ERR_get_state();
    VR_CRYPTO_free_ex_index(0, -1);
    idx = VR_SSL_get_ex_data_X509_STORE_CTX_idx();
    FuzzerSetRand();
    comp_methods = VR_SSL_COMP_get_compression_methods();
    if (comp_methods != NULL)
        sk_SSL_COMP_sort(comp_methods);

    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    SSL *server;
    BIO *in;
    BIO *out;
#if !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_DSA)
    BIO *bio_buf;
#endif
    SSL_CTX *ctx;
    int ret;
    RSA *privkey;
    const uint8_t *bufp;
    EVP_PKEY *pkey;
    X509 *cert;
#ifndef OPENSSL_NO_EC
    EC_KEY *ecdsakey = NULL;
#endif
#ifndef OPENSSL_NO_DSA
    DSA *dsakey = NULL;
#endif
    uint8_t opt;

    if (len < 2)
        return 0;

    /*
     * TODO: use the ossltest engine (optionally?) to disable crypto checks.
     */

    /* This only fuzzes the initial flow from the client so far. */
    ctx = VR_SSL_CTX_new(SSLv23_method());

    ret = VR_SSL_CTX_set_min_proto_version(ctx, 0);
    OPENSSL_assert(ret == 1);
    ret = VR_SSL_CTX_set_cipher_list(ctx, "ALL:eNULL:@SECLEVEL=0");
    OPENSSL_assert(ret == 1);

    /* RSA */
    bufp = kRSAPrivateKeyDER;
    privkey = VR_d2i_RSAPrivateKey(NULL, &bufp, sizeof(kRSAPrivateKeyDER));
    OPENSSL_assert(privkey != NULL);
    pkey = VR_EVP_PKEY_new();
    VR_EVP_PKEY_assign_RSA(pkey, privkey);
    ret = VR_SSL_CTX_use_PrivateKey(ctx, pkey);
    OPENSSL_assert(ret == 1);
    VR_EVP_PKEY_free(pkey);

    bufp = kCertificateDER;
    cert = VR_d2i_X509(NULL, &bufp, sizeof(kCertificateDER));
    OPENSSL_assert(cert != NULL);
    ret = VR_SSL_CTX_use_certificate(ctx, cert);
    OPENSSL_assert(ret == 1);
    VR_X509_free(cert);

#ifndef OPENSSL_NO_EC
    /* ECDSA */
    bio_buf = VR_BIO_new(VR_BIO_s_mem());
    OPENSSL_assert((size_t)VR_BIO_write(bio_buf, ECDSAPrivateKeyPEM, sizeof(ECDSAPrivateKeyPEM)) == sizeof(ECDSAPrivateKeyPEM));
    ecdsakey = VR_PEM_read_bio_ECPrivateKey(bio_buf, NULL, NULL, NULL);
    VR_ERR_print_errors_fp(stderr);
    OPENSSL_assert(ecdsakey != NULL);
    VR_BIO_free(bio_buf);
    pkey = VR_EVP_PKEY_new();
    VR_EVP_PKEY_assign_EC_KEY(pkey, ecdsakey);
    ret = VR_SSL_CTX_use_PrivateKey(ctx, pkey);
    OPENSSL_assert(ret == 1);
    VR_EVP_PKEY_free(pkey);

    bio_buf = VR_BIO_new(VR_BIO_s_mem());
    OPENSSL_assert((size_t)VR_BIO_write(bio_buf, ECDSACertPEM, sizeof(ECDSACertPEM)) == sizeof(ECDSACertPEM));
    cert = VR_PEM_read_bio_X509(bio_buf, NULL, NULL, NULL);
    OPENSSL_assert(cert != NULL);
    VR_BIO_free(bio_buf);
    ret = VR_SSL_CTX_use_certificate(ctx, cert);
    OPENSSL_assert(ret == 1);
    VR_X509_free(cert);
#endif

#ifndef OPENSSL_NO_DSA
    /* DSA */
    bio_buf = VR_BIO_new(VR_BIO_s_mem());
    OPENSSL_assert((size_t)VR_BIO_write(bio_buf, DSAPrivateKeyPEM, sizeof(DSAPrivateKeyPEM)) == sizeof(DSAPrivateKeyPEM));
    dsakey = VR_PEM_read_bio_DSAPrivateKey(bio_buf, NULL, NULL, NULL);
    VR_ERR_print_errors_fp(stderr);
    OPENSSL_assert(dsakey != NULL);
    VR_BIO_free(bio_buf);
    pkey = VR_EVP_PKEY_new();
    VR_EVP_PKEY_assign_DSA(pkey, dsakey);
    ret = VR_SSL_CTX_use_PrivateKey(ctx, pkey);
    OPENSSL_assert(ret == 1);
    VR_EVP_PKEY_free(pkey);

    bio_buf = VR_BIO_new(VR_BIO_s_mem());
    OPENSSL_assert((size_t)VR_BIO_write(bio_buf, DSACertPEM, sizeof(DSACertPEM)) == sizeof(DSACertPEM));
    cert = VR_PEM_read_bio_X509(bio_buf, NULL, NULL, NULL);
    OPENSSL_assert(cert != NULL);
    VR_BIO_free(bio_buf);
    ret = VR_SSL_CTX_use_certificate(ctx, cert);
    OPENSSL_assert(ret == 1);
    VR_X509_free(cert);
#endif

    /* TODO: Set up support for SRP and PSK */

    server = VR_SSL_new(ctx);
    in = VR_BIO_new(VR_BIO_s_mem());
    out = VR_BIO_new(VR_BIO_s_mem());
    VR_SSL_set_bio(server, in, out);
    VR_SSL_set_accept_state(server);

    opt = (uint8_t)buf[len-1];
    len--;

    OPENSSL_assert((size_t)VR_BIO_write(in, buf, len) == len);

    if ((opt & 0x01) != 0)
    {
        do {
            char early_buf[16384];
            size_t early_len;
            ret = VR_SSL_read_early_data(server, early_buf, sizeof(early_buf), &early_len);

            if (ret != SSL_READ_EARLY_DATA_SUCCESS)
                break;
        } while (1);
    }

    if (VR_SSL_do_handshake(server) == 1) {
        /* Keep reading application data until error or EOF. */
        uint8_t tmp[1024];
        for (;;) {
            if (VR_SSL_read(server, tmp, sizeof(tmp)) <= 0) {
                break;
            }
        }
    }
    VR_SSL_free(server);
    VR_ERR_clear_error();
    VR_SSL_CTX_free(ctx);

    return 0;
}

void FuzzerCleanup(void)
{
}
