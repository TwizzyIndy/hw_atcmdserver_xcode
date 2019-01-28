// This file is part of Synecdoche.
// http://synecdoche.googlecode.com/
// Copyright (C) 2005 University of California
//
// Synecdoche is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Synecdoche is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License with Synecdoche.  If not, see <http://www.gnu.org/licenses/>.

#ifndef H_CRYPT
#define H_CRYPT

#include <stdio.h>
#include <stdbool.h>

#include "rsaref.h"

//#include <openssl/rsa.h>

/*
#define MAX_RSA_MODULUS_BITS 1024
#define MAX_RSA_MODULUS_LEN ((MAX_RSA_MODULUS_BITS + 7) / 8)
#define MAX_RSA_PRIME_BITS ((MAX_RSA_MODULUS_BITS + 1) / 2)
#define MAX_RSA_PRIME_LEN ((MAX_RSA_PRIME_BITS + 7) / 8)


typedef struct {
    unsigned short int bits;                     ///< length in bits of modulus
    unsigned char modulus[MAX_RSA_MODULUS_LEN];  ///< modulus
    unsigned char exponent[MAX_RSA_MODULUS_LEN]; ///< public exponent
} R_RSA_PUBLIC_KEY;

typedef struct {
    unsigned short int bits;                     ///< length in bits of modulus
    unsigned char modulus[MAX_RSA_MODULUS_LEN];  ///< modulus
    unsigned char publicExponent[MAX_RSA_MODULUS_LEN];     ///< public exponent
    unsigned char exponent[MAX_RSA_MODULUS_LEN]; ///< private exponent
    unsigned char prime[2][MAX_RSA_PRIME_LEN];   ///< prime factors
    unsigned char primeExponent[2][MAX_RSA_PRIME_LEN];     ///< exponents for CRT
    unsigned char coefficient[MAX_RSA_PRIME_LEN];          ///< CRT coefficient
} R_RSA_PRIVATE_KEY;
*/
// functions to convert between OpenSSL's keys (using BIGNUMs)
// and our binary format

void openssl_to_keys(
                     RSA* rp, int nbits, R_RSA_PRIVATE_KEY* priv, R_RSA_PUBLIC_KEY* pub
                     );
void private_to_openssl(R_RSA_PRIVATE_KEY* priv, RSA* rp);
void public_to_openssl(R_RSA_PUBLIC_KEY* pub, RSA* rp);

struct KEY {
    unsigned short int bits;
    unsigned char data[1];
};

struct DATA_BLOCK {
    unsigned char* data;
    unsigned int len;
};

#define MIN_OUT_BUFFER_SIZE MAX_RSA_MODULUS_LEN+1

/// the size of a binary signature (encrypted MD5)
#define SIGNATURE_SIZE_BINARY MIN_OUT_BUFFER_SIZE

/// size of text-encoded signature
#define SIGNATURE_SIZE_TEXT (SIGNATURE_SIZE_BINARY*2+20)

int print_hex_data(FILE* f, struct DATA_BLOCK* block);
int sprint_hex_data(char* p, struct DATA_BLOCK* block);
int scan_hex_data(FILE* f, struct DATA_BLOCK* block);
int print_key_hex(FILE* f, struct KEY* key, int len);
int scan_key_hex(FILE* f, struct KEY* key, int len);
int sscan_key_hex(const char* buf, struct KEY* key, int len);
int encrypt_private(
                    R_RSA_PRIVATE_KEY* key, struct DATA_BLOCK* input, struct DATA_BLOCK* output
                    );
int decrypt_public(
                   R_RSA_PUBLIC_KEY* key, struct DATA_BLOCK* input, struct DATA_BLOCK* output
                   );
//int sign_file(
//              const char* path, R_RSA_PRIVATE_KEY* key, struct DATA_BLOCK* signature
//              );
//int sign_block(
//               struct DATA_BLOCK* data, R_RSA_PRIVATE_KEY* key, struct DATA_BLOCK* signature
//               );
//int verify_file(
//                const char* path, R_RSA_PUBLIC_KEY* key, struct DATA_BLOCK* signature, bool* answer
//                );
//int verify_file2(
//                 const char* path, const char* signature, const char* key, bool* answer
//                 );
//int verify_string(
//                  const char* text, const char* signature, R_RSA_PUBLIC_KEY*, bool* answer
//                  );
//int verify_string2(
//                   const char* text, const char* signature, const char* key, bool* answer
//                   );

//int read_key_file(const char* keyfile, R_RSA_PRIVATE_KEY* key);
//int generate_signature(
//                       char* text_to_sign, char* signature_hex, R_RSA_PRIVATE_KEY* key
//                       );

#endif
