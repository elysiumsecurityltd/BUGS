/*
 *  extra.c
 *
 *   EXTRA BUGS FUNCTION 
 *
 *   EXTRA MISCALLENAOUS FUNCTIONS 
 *   Version 1.5
 *   17 January 2020 
 *
 *  -> new getchar() function
 *  -> Locate text on the screen function
 *  -> Erase screen function  
 *  -> Signal interrupt function  
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

/*
 * HISTORY
 *
 *
 * --- V 1.5 ---
 * 
 * 17/01/2020 : - Added defined (__APPLE__) test
 *
 * --- V 1.4 ---
 *
 * 16/07/2000 : - Changed the BSD flag detection to also accept OpenBSD
 *		  and FreeBSD as well as BSD
 *
 *
 * --- V 1.3 ---
 *
 * 19/05/1998 : - Added 2 new parameters for gotoxy, line and col
 *		  allowing you to specify the size of your terminal
 *
 * --- V 1.2 ---
 *
 * 12/05/1998 : - Added the BSD compilation option
 *
 * --- V 1.1 ---
 *
 * 18/01/1998 : - I changed the bcrypt_signal function, I now use
 *		  the standard signal() function.
 *		  Then I can compile on Silicon Graphics
 *
 * --- V 1.0 ---
 *
 * 17/01/1998 : - First realase.
 *
 */

#include "../include/extra.h"


/*
 * Function based on Allain Pillot's one
 * (IUT A LYON 1, FRANCE)
 * Modification by Martinez Sylvain
 * This may not work on all OS !!!!!!!!
 *
 * It is just a function take a char from the standard input
 * but do not wait if nothing is typed.
 */
char
bcrypt_vol (int tempvar)
{
  char c;
#if defined(__FreeBSD__) | defined (__NetBSD__) | defined (__OpenBSD__) | defined (__APPLE__)
  struct termios conf;
#else
  struct termio conf;
#endif

  unsigned char anc_vmin, anc_vtime;

/*
 * Take the configuration
 */
#if defined(__FreeBSD__)
  ioctl (0, TIOCGETA, &conf);
#else
  ioctl (0, TCGETA, &conf);
#endif  
  anc_vmin = conf.c_cc[VMIN];
  anc_vtime = conf.c_cc[VMIN];
  conf.c_lflag &= ~(ICANON | ECHO); 
  conf.c_cc[VMIN] = tempvar;    

/*
 * How long do we have to wait a char
 */
  conf.c_cc[VTIME] = 0;         

/*
 * Initialisation of the new configuration
 */ 
#if defined(__FreeBSD__)
  ioctl (0, TIOCSETA, &conf);
#else
  ioctl (0, TCSETA, &conf);
#endif  
  c = getchar ();

/* 
 * We do that instead of doing :
 * rewind(stdout) + read(0,&c,1)          
 */
  conf.c_lflag |= (ICANON | ECHO);
  conf.c_cc[VMIN] = anc_vmin;
  conf.c_cc[VTIME] = anc_vtime;

/*
 * Validation of the old configuration
 */
#if defined(__FreeBSD__)
  ioctl (0, TIOCSETA, &conf);
#else
  ioctl (0, TCSETA, &conf);
#endif  
  return c;
}


/*
 * SIGNAL INTERUPT FUNCTION
 * Use to stop any signal sent to the program
 */
void
bcrypt_signal ()
{

/*
 * I stop any signals sent to the application
 * that used this function.
 * like ^D, ^C, ^Z, etc
 * I also stop signals that I think are dangerous,
 * or if I don't really know what they are ...
 * If I forgot to stop some signals, or if
 * I stop some not dangerous signals,
 * please tell me ! :)
 */
signal(SIGHUP,bcrypt_end);
signal(SIGINT,bcrypt_end);
signal(SIGQUIT,bcrypt_end);
signal(SIGTRAP,bcrypt_end);
signal(SIGABRT,bcrypt_end);
signal(SIGKILL,bcrypt_end);
signal(SIGPIPE,bcrypt_end);
signal(SIGSTOP,bcrypt_end);
signal(SIGTSTP,bcrypt_end);

/* 
 * I do not stop the following signal
 * The reason is that on Silicon Graphics 
 * when I do a clear, this signal is intercepted
 */
/*
signal(SIGCHLD,bcrypt_end);
*/
}


void
bcrypt_end (int sig)
{
printf("\n Signal intercepted and ignored : %d \n",sig);
bcrypt_signal();
}


/*
 * When you want to print text at a certain position on the screen
 */
void gotoxy(int x,int y, int line, int col)
{
line++;
col++;
  printf("\033[%d;%df",y % line,x % col);
}


