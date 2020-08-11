/*  
 *  shuffle.h
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

#ifndef _BUGSCRYPT_SHUFFLE_H
#define _BUGSCRYPT_SHUFFLE_H

#include "bstandard.h"

int bcrypt_file_shuffle (FILE *, int *, int, TYPE_INT *,
                       int, int, int, int, int, globalvar *);
int bcrypt_mem_shuffle (TYPE_INT *, int, int *, int, TYPE_INT *,
                       int, int, int, globalvar *);
int bcrypt_file_unshuffle (FILE *, int *, int, TYPE_INT *,
                       int, int, int, int, int, globalvar *);
int bcrypt_mem_unshuffle (TYPE_INT *, int, int *, int, TYPE_INT *,
                       int, int, int, globalvar *);

#endif
