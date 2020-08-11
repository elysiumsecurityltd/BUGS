/*  
 *  utils.h
 *
 *
 *  B U G S     LIBRARY     HEADER  
 *
 *   Dynamic CRYPTOGRAPHY ALGORITHM
 *   Version 4.0.0 - "ARMISTICE"
 *   19 November 2000
 *
 *  -> make multi-users programms
 *  -> generate passwd
 *  -> crypt file
 *
 *   Realised by MARTINEZ Sylvain
 *
 *   Based on the BUGS crypt's algorithm of MARTINEZ Sylvain
 *   (Big and Usefull Great Security)
 *
 *  Copyright 1996-2000 MARTINEZ Sylvain
 *  THIS IS FREE SOFTWARE; YOU CAN REDISTRIBUTE IT AND/OR MODIFY IT UNDER
 *  THE TERMS OF THE GNU GENERAL PUBLIC LICENSE, see the file COPYING.
 */                                                                    

#ifndef _BUGSCRYPT_UTILS_H
#define _BUGSCRYPT_UTILS_H

#include "bstandard.h"

int bcrypt_fread_int (TYPE_INT *, int, int, FILE *, globalvar *, int);
int bcrypt_fwrite_int (TYPE_INT *, int, int, FILE *, globalvar *, int);
TYPE_INT long_rand(TYPE_INT *, globalvar *, int);
int lfsr(TYPE_INT *, globalvar *);
TYPE_INT isaac(globalvar *, int);
TYPE_INT brand(globalvar *, int);
RETURN_TYPE bpow(int , int);
RETURN_TYPE bclean_string(unsigned char *, int, int);
RETURN_TYPE bclean_typeint(TYPE_INT *, int, int);
RETURN_TYPE bssl(int, int *, int *, int *,globalvar *, int);

#endif
