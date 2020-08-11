/*  
 *  wrapper.h
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

#ifndef _BUGSCRYPT_WRAPPER_H
#define _BUGSCRYPT_WRAPPER_H

#include "bstandard.h"

RETURN_TYPE binit  (int, int, char *, int, globalvar *);

RETURN_TYPE bkey_generator (unsigned char *, int, int, char *,int, int, int,
								 globalvar *);
RETURN_TYPE bfile (int, char *, char *, char *, unsigned char *, int, int,
		 int, int, int, int, int, globalvar *);
RETURN_TYPE bstream (int, unsigned char *, int, char *, unsigned char *, int, int,
		 int, int, int, globalvar *);

/*
 * These functions are not used on Windows95
 */
int bpass (TYPE_INT *, unsigned char *, int, int, int, int, globalvar *);
int blogin (TYPE_INT *, unsigned char *, int, int, int, int, globalvar *);

#endif
