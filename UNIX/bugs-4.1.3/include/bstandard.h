/*  
 *  bstandard.h
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

#ifndef _BUGSCRYPT_STANDARD_H
#define _BUGSCRYPT_STANDARD_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h> 

/*
 * Compatibility with Windows 9X/2000 Borland C++ DLL
 * With BC 4.5 or laster, replace the line :
 * #define RETURN_TYPE extern "C" __declspec(dllexport) int FAR PASCAL
 * by
 * #define RETURN_TYPE extern int FAR PASCAL 
 */
#ifndef RETURN_TYPE
 #if defined(__WIN32__)
 #include <windows.h>
 #if defined _BUGSCRYPT_DLL
 	#define RETURN_TYPE extern "C" __declspec(dllexport) unsigned int
 #else
 	#define RETURN_TYPE extern "C" __declspec(dllimport) unsigned int
 #endif
 #else 
  #define RETURN_TYPE unsigned int
 #endif
#endif
/*
 * Type of int that I will use
 * Default = long = 4 bytes = 32 bits 
 * int = 2 bytes = 16 bits 
 * long long = 8 bytes = 64 bits
 *
 * Yes, I prefer to do a #define for that,
 * because if a system has no long type I can easly
 * change the type without changing my C source code. 
 * !!!!! ALWAY USE UNSIGNED TYPE !!!!!!
 * !!!!! RETURN_TYPE MUST BE THE SAME AS TYPE_INT !!!!!
 */ 
#ifndef TYPE_INT
 #define TYPE_INT unsigned int 
#endif

/*
 * NB_BYTE     : Lenght in bytes of the int I am using
 * NB_BITS     : Length in bits of the int I am using
 * NB_SHIFT    : shift to use for the division in bcrypt_swap()
 * KEYLENGTH   : Length of the key used to crypt
 * NB_INDEX    : Number of index of the aray that will contain the cipher text
 * NB_CHAR     : Number of characters of the cipher text and of the clear text
 * USER_LENGTH : Length of the username you can use
 * RANDOM      : Random Number Generator algorithm to use
 * SEED        : Initial Seed to use with the RNG
 * MISC        : if set to 1 then the library will stop
 *               (this is useful if you are using BUGS in a Thread)
 * PROGRESS    : This should show an estimation of the encryption
 *		         /decryption progress
 *		         PLEASE NOTE IT COULD BE >100
 * KEY_BUFFER  : Number of key that will be stored in the key buffer used in
 *               seed()
 * BCRYPT_ENDIAN: If set to 1 then your computer is using 
 *		          big endian to store data.
 * VERSION     : Libcrypt version number (as a string)
 */
#ifndef _GLOBAL_STRUCT
 #define _GLOBAL_STRUCT 
 typedef struct
         {
          int NB_BYTE;
          int NB_BITS;
          int NB_SHIFT;
          int KEYLENGTH;
          int NB_INDEX;
          int NB_CHAR;
          int USER_LENGTH;
          int RANDOM;
          TYPE_INT SEED;
          int MISC;
          int PROGRESS;
          int KEY_BUFFER;
          int BCRYPT_ENDIAN;
          char LIB_VERSION[10]; 
         }
 globalvar;
#endif

/*
 * Log file
 */
#ifndef _BCRYPTLOG
 #define _BCRYPTLOG
 FILE *BCRYPTLOG;
#endif

#define BUGS_START  "[BUGS_ASCII_MODE_v04_START]"
#define BUGS_END    "[BUGS_ASCII_MODE_v04_END]"  
/*
 * globalvar->MISC variable MASKS
 */
#ifndef _BCRYPT_MASKS
 #define _BCRYPT_MASKS

/*
 * globalvar->MISC variable MASKS
 */
 #define BMASK_STOP 1
 #define BMASK_ROUND 2
 #define BMASK_SWAP 4
 #define BMASK_SHUFFLE 8
 #define BMASK_BUFFER 16

/*
 * BSSL Preset Security Level
 */ 
 #define BSSL_VLOW   1
 #define BSSL_LOW    2
 #define BSSL_MEDIUM 3
 #define BSSL_HIGH   4
 #define BSSL_VHIGH  5 
#endif

/*
 * BSSL Preset Security Level
 */

#endif
