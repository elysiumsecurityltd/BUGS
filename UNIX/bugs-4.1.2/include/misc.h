/*  
 *  misc.h
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

#ifndef _BUGSCRYPT_MISC_H
#define _BUGSCRYPT_MISC_H

#include "bstandard.h" 

TYPE_INT  bcrypt_read_key (TYPE_INT *, TYPE_INT *, int, globalvar *);

int bcrypt_comparison (TYPE_INT *, TYPE_INT *, int, globalvar *);
int bcrypt_test_passwd (int, TYPE_INT *, unsigned char *, int, int,
                        globalvar *);

int bcrypt_read_keyfile (unsigned char *, char *, int, globalvar *);
int bcrypt_write_keyfile (unsigned char *, char *, int, globalvar *);
RETURN_TYPE bcrypt_write_hide (int, char *, char *, globalvar *,int);
RETURN_TYPE bcrypt_read_hide (int, char *, char *, globalvar *, int);

int bcrypt_read_passwd (char *, char *, TYPE_INT *, int, globalvar *);
int bcrypt_write_passwd (char *, TYPE_INT *, char *, int, globalvar *);
int bcrypt_delete_passwd (char *, char *, int, int, globalvar *);

#endif
