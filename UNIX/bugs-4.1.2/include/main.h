/*  
 *  main.h
 *
 *
 *  B U G S     LIBRARY     HEADER  
 *
 *   Dynamic CRYPTOGRAPHY ALGORITHM
 *   Version 4.0.0 
 *   19 November 2000
 *
 *  -> make multi-users programms
 *  -> generate passwd
 *  -> crypt file
 *
 *   Created by Sylvain MARTINEZ
 *
 *   Based on the BUGS crypt's algorithm of Sylvain Martinez
 *   (Big and Usefull Great Security)
 *
 *  Copyright 1996-2003 Sylvain MARTINEZ
 *  THIS IS FREE SOFTWARE; YOU CAN REDISTRIBUTE IT AND/OR MODIFY IT UNDER
 *  THE TERMS OF THE GNU GENERAL PUBLIC LICENSE, see the file COPYING.
 */

#ifndef _BUGSCRYPT_MAIN_H
#define _BUGSCRYPT_MAIN_H

#include "bstandard.h"

int bcrypt_transcription (unsigned char *, TYPE_INT *,
			 int, globalvar *);
int bcrypt_add (TYPE_INT *, int, globalvar *);
int bcrypt_test_length (unsigned char *, int, int, globalvar *);
int bcrypt_swap (TYPE_INT *, int,  int, globalvar *);
int bcrypt_code (int, TYPE_INT, TYPE_INT *, int, globalvar *);

#endif
