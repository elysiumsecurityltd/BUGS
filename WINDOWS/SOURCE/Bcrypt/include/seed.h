/*  
 *  seed.h
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

#ifndef _BUGSCRYPT_SEED_H
#define _BUGSCRYPT_SEED_H

#include "bstandard.h"

int bcrypt_file_seed (FILE *, FILE *, int *, int, TYPE_INT *, int,
                       int, int, int, globalvar *);

int bcrypt_file_seed_prob (int, FILE *, FILE *, int *, int, TYPE_INT *, TYPE_INT *,
			int, int, int, int, int, globalvar *);

int bcrypt_mem_seed (TYPE_INT *, int, int *, int, TYPE_INT *, int,
                       int, globalvar *);
int bcrypt_mem_seed_prob (int, TYPE_INT *, int, int *, int, TYPE_INT *, TYPE_INT *,
			int, int, globalvar *);

#endif
