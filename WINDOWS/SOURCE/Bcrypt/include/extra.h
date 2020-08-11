/*
 *  extra.h
 *
 *   EXTRA BUGS HEADER 
 *
 *   EXTRA MISCALLENAOUS FUNCTIONS 
 *   Version 1.4
 *   16 July 2000 
 *
 *  -> new getchar() function
 *  -> Locate text on the screen function
 *  -> Erase screen function  
 *  -> Signal interrupt function  
 *
 *   Realised by MARTINEZ Sylvain
 *
 *   Based on the BUGS crypt's algorithm of MARTINEZ Sylvain
 *   (Big and Usefull Great Security)
 *                                      
 *  Copyright (C) 1996-2000 MARTINEZ Sylvain
 *  THIS IS FREE SOFTWARE; YOU CAN REDISTRIBUTE IT AND/OR MODIFY IT UNDER
 *  THE TERMS OF THE GNU GENERAL PUBLIC LICENSE, see the file COPYING.
 * 
 */

#ifndef _EXTRA_H
#define _extra_h

#include <stdio.h>

#if defined(__FreeBSD__) | defined (__OpenBSD__) | defined (__NetBSD__)  
#include <sys/termios.h>
#include <sys/ttycom.h>
#else 
#include <termio.h>
#endif

/*
 * not tried on FreeBSD
 */
#if defined (__OpenBSD__) | defined (__NetBSD__)
#define TCGETA TIOCGETA
#define TCSETA TIOCSETA
#endif

/*
 * Used for the bcrypt_vol() function
 * only tested on Linux and HPUX
 */
#include <sys/ioctl.h>

/*
 * These 2 headers are needed to use umask()
 */
#include <sys/types.h>
#include <sys/stat.h>
/*
 * I use this header to stop any signal that can be send to the program
 */
#include <signal.h>

char bcrypt_vol(int);
void bcrypt_signal();
void bcrypt_end(int);
void gotoxy(int,int,int,int);

#endif






