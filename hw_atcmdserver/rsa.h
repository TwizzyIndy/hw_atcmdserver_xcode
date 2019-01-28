/* RSA.H - header file for RSA.C
 */

/* Copyright (C) RSA Laboratories, a division of RSA Data Security,
     Inc., created 1991. All rights reserved.
 */

int HWRSAPublicEncrypt PROTO_LIST((unsigned char*, unsigned int, unsigned char *, unsigned int*,R_RSA_PUBLIC_KEY *));

int RSAPublicEncrypt PROTO_LIST 
  ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    R_RSA_PUBLIC_KEY *, R_RANDOM_STRUCT *));

int RSAPublicDecrypt PROTO_LIST
((unsigned char *, unsigned int *, unsigned char *, unsigned int,
  R_RSA_PUBLIC_KEY *));

int RSAPrivateEncrypt PROTO_LIST
  ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    R_RSA_PRIVATE_KEY *));

int RSAPrivateDecrypt PROTO_LIST
  ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    R_RSA_PRIVATE_KEY *));

int RSAPublicBlock PROTO_LIST
((unsigned char *, unsigned int *, unsigned char *, unsigned int,
  R_RSA_PUBLIC_KEY *));
int RSAPrivateBlock PROTO_LIST
((unsigned char *, unsigned int *, unsigned char *, unsigned int,
  R_RSA_PRIVATE_KEY *));
