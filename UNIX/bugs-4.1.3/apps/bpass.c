/*  
 *  bpass.c
 *
 *  Version  2.3 
 *  03 October 2000 
 *
 *   PASSWORD GENERATOR AND MANAGEMENT
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
 * --- V 2.3 ---
 *
 * 03/10/2000:  - Added a '\0' after each strncpy as this is not done automatically
 *                on all OS.
 *
 *
 * --- V 2.2 ---
 *
 * 15/09/2000:  - Added the error output file option
 *
 * --- V 2.1 ---
 *
 * 16/07/2000:  - New option: RNG selector
 *		- Added a parameter to binit: RANDOM
 *
 * 06/07/2000:  - Minor problem in the way I was allocating memory for
 *                the variables receiving the FILE NAMES.
 *                This could cause problem when using filename < 3
 *
 * --- V 2.0 ---
 *
 * 24/04/2000: 	- First implementation with the new library
 *
 * --- V 1.9 ---
 *
 * 26/07/1999 : - Replaced sizeof() by strlen() while calling malloc()
 *  
 * 23/07/1999 : - Changed the way I handle parameters 
 *		- Added some parameters (keylength and verbose mode)
 *		- Corrected minor bugs
 *
 * 09/07/1999 : - Changed pass_clear from char to unsigned char
 *
 * --- V 1.8 ---
 *
 * 16/02/1998 : - Corrected the input password bug
 *		- Changed bcrypt initialisation (binit)
 *
 * --- V 1.7 ---
 *
 * 07/02/1998 : - Added the libcrypt version number
 *
 * --- V 1.6 ---
 *
 * 27/01/1998 : - Cleaned the source code
 *
 * --- V 1.5 ---
 *
 * 19/01/1998 : - I added USER_LENGTH to varinit
 *
 * 17/01/1998 : - Change some variable names
 *
 * 15/01/1998 : - Added a malloc for the *varinit variable
 *
 * 11/01/1998 : - added global variable VERSION
 *              - Started to do an HISTORY
 */

/*
 * This header is important
 * There is some global variables that you will need, eg:
 * USER_LENGTH = size of the string that contain the user name
 * other reserved variable name : KEYLENGTH, varinit->NB_CHAR, varinit->NB_INDEX, etc
 * Read the documentation or have a look of this header for more information
 */
#include "../include/wrapper.h"
#include "../include/utils.h" 
#include "../include/misc.h"
#include "../include/extra.h"

char *VERSION="v2.3, October 2000";

/*
 * ASCII code for the RETURN charactere that may change on different OS 
 */
const int BCRYPT_RETURN = 10;	

/*
   * Default : mode = 0 (non verbose)
   *           Key's length = 128 bits
   */
  int MODE = 1;
  int ROUND = 2;
  int PARAM_KEY = 128;
  int RANDOM = 1;
  char PARAM_USER[200];
  char PARAM_ERRORFILE[200];
  int PARAM_ERROR = 0;
  globalvar *varinit;

  /*
   * Passwd file
   */
  char *path="bpasswd";
  
/*
 * Functions
 */
void usage(void);
int argcheck(int, char **);
int init(void);
int pass(char **);

int 
main (int argc, char **argv)
{

/*
 * Use the following function to protect this program
 * against signal : not possible to interupt it
 */
  bcrypt_signal(); 

  if (argcheck(argc, argv) == 0) return 0;
  if (init() == 0) return 0;
  /*
   * I use umask because I want the bpasswd file to be created
   * with the following permissions: rw-r--r--
   */
  umask(022);
  if (pass(argv) == 0)
  {
   umask(002);
   return 0;
  }

 umask(002);
 return 1;
}
 
/*
 * Passwd generator function
 */
int pass(char **argv)
{
  char *pass_verif, carac;

  int i, length, status = 0, test;
  
  unsigned char *pass_clear;
  TYPE_INT *code_file, *passwd;

  test = 1;

passwd = (TYPE_INT *) malloc(varinit->NB_CHAR);
code_file = (TYPE_INT *) malloc(varinit->NB_CHAR);
pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);
pass_verif = (char *) malloc (varinit->NB_CHAR);

printf("\n Bpass %s, Martinez Sylvain",VERSION);
printf("\n BUGS ALGORITHM PASSWORD GENERATOR AND MANAGEMENT"); 
printf("\n Libcrypt version : '%s'",varinit->LIB_VERSION);
printf("\n\n Password generation in progress.");
printf("\n KEY'S LENGTH used : %d.",PARAM_KEY);
printf("\n Password file : '%s'.\n",path);
printf("\n WARNING: you can't have different password length in the same password file.\n");

if (strlen(PARAM_USER) > varinit->USER_LENGTH)
{
 printf("\n User Name length is too big. Max = '%d' characters. \n ERROR.\n",varinit->USER_LENGTH);
 return 0;
}

  if (bcrypt_read_passwd (PARAM_USER, path, code_file, MODE, varinit) == 0)
    {
      printf ("\n %s is a new USER ", PARAM_USER);
    }
  else
    {
      printf ("\n Changing passwd for %s ", PARAM_USER);
      printf ("\n Old Password -> ");
      i = 0;
      do
	{
	  carac = bcrypt_vol (1);
	  if (carac != BCRYPT_RETURN) pass_clear[i] = carac;
            i++;
	}
      while (i < varinit->NB_CHAR && (carac != BCRYPT_RETURN));

      if (carac == BCRYPT_RETURN)
         {
          pass_clear[i - 1] = '\0';
          length = i - 1;
         }
      else
        length = i;


      test = blogin (code_file, pass_clear, length, 0, ROUND, MODE, varinit);
    }

  if (test == 0)
    status = 2;

  /* 
   * Changing passwd 
   */
  if (status == 0)
    {
      i = 0;
      printf ("\n New Password -> ");
      do
	{
	  carac = bcrypt_vol (1);
	  if (carac != BCRYPT_RETURN)
                         pass_clear[i] = carac;
             
          i++;
	}
      while ((i < varinit->NB_CHAR) && (carac != BCRYPT_RETURN));
      if (carac == BCRYPT_RETURN)
         {
	  pass_clear[i - 1] = '\0';
          length = i - 1;
         }
       else
          length = i;

      if (length >= (varinit->NB_CHAR / 2))
	{
	  printf ("\n Re-type New Passwd -> ");
	  i = 0;
	  do
	    {
	      carac = bcrypt_vol (1);
	      if (carac != BCRYPT_RETURN)
                          pass_verif[i] = carac;
              i++;
	    }
	  while ((i < varinit->NB_CHAR) && (carac != BCRYPT_RETURN));
	  if (carac == BCRYPT_RETURN)
             {
	      pass_verif[i - 1] = '\0';
              length = i - 1;
             }
          else
              length = i;


 	  if (strcmp ((char *)pass_clear, pass_verif) == 0)
	    {
	      if (bpass (passwd, pass_clear, length, 0, ROUND, MODE, varinit) == 0)
		status = 4;

/*
 * I test if the cipher text already exist, if yes, I try to crypt again
 * the clear text, I try 10 times until I generate an error
 */
	i=0;
	      if (status != 4 && bcrypt_write_passwd (PARAM_USER, passwd, path,
                                                             MODE, varinit) == 0)
		{
		  while ((bpass (passwd, pass_clear, length, ROUND, 0,MODE,
                                  varinit) == 0)
      		          && (i < 10))
 		    i++;
 		}
	      if (i == 10)
		status = 4;

	    }
	  else
	    status = 3;
	}
      else
	status = 1;
    }

  if (status == 1)
    printf ("\n %d letters minimum and %d letters maximum ...\n", (varinit->NB_CHAR / 2), varinit->NB_CHAR);
  if (status == 2)
    printf ("\n Illegal passwd, imposter\n");
  if (status == 3)
    printf ("\n You misspelled it. Passwd not changed.\n");
  if (status == 4)
    printf ("\n Your passwd isn't good. Change it.\n");
  if (status == 0)
    {
      printf ("\n Passwd CHANGED.\n");
      return 1;
    }

  return 0;
}


/*
 * Initialised the global variables
 */
int init()
{
varinit = (globalvar *) malloc(sizeof(globalvar));
/*
 * The log will be generated in the stderr output
 */
binit(PARAM_KEY, RANDOM, PARAM_ERRORFILE, PARAM_ERROR, varinit);
return 1;
}

/* 
 * Check the parameter of the program
 */
int argcheck(int argc, char **argv)
{
  int i;

  for (i = 0; i < argc; i++)
      {
	if ((0 == strcmp(argv[i],"-u")) && (i+1 < argc))
	   {
                 if (strlen(argv[i+1]) >= 200)
                    {
                     printf("\n ERROR. \nUSER name is too long. \n\n");
                     return 0;
                    }

	    strcpy(PARAM_USER, argv[i+1]);
	    PARAM_USER[strlen(argv[i+1])]='\0';
	   }
	else if ((0 == strcmp(argv[i],"-k")) && (i+1 < argc)) PARAM_KEY= atoi(argv[i+1]);
        else if ((strcmp(argv[i],"-r") == 0) && (i+1 < argc)) RANDOM=atoi(argv[i+1]);
	else if (0 == strcmp(argv[i],"-quiet")) MODE = 0;
	else if (0 == strcmp(argv[i],"-v")) MODE = 2;
	else if ((0 == strcmp(argv[i],"-round")) && (i+1 < argc)) ROUND = atoi(argv[i+1]);
	else if ((strcmp(argv[i],"-ef") == 0) && (i+1 < argc))
		{

	         if (strlen(argv[i+1]) >= 200)
		    {
		     printf("\n ERROR. \nERROR file name is too long. \n\n");
		     return 0;
		    }
		 strncpy(PARAM_ERRORFILE, argv[i+1],strlen(argv[i+1]));
		 PARAM_ERRORFILE[strlen(argv[i+1])]='\0';
		 PARAM_ERROR = 1;
		}
        else if (strcmp(argv[i],"-ef") == 0)
		{
		PARAM_ERROR = 1;
		strcpy(PARAM_ERRORFILE,"bpass.log");
                PARAM_ERRORFILE[strlen("bpass.log")]='\0';
		}

      }
       	
   if (0 == strcmp(PARAM_USER,""))
	{
	usage();
	return 0;
	}

return 1;
}

void usage()
{
   printf("\n BPASS %s, (C) Martinez Sylvain",VERSION);
   printf("\n BUGS ALGORITHM PASSWORD GENERATOR AND MANAGEMENT"); 
   printf("\n\n Usage: bpass -u USER_NAME {OPTIONS}");
   printf("\n\n {OPTIONS} :");
   printf("\n  -k nb    : KEYLENGTH which has to be a 2 multiple integer.");
   printf("\n             At least 32.");
   printf("\n             DEFAULT = 128"); 	
   printf("\n  -r nb       : Random Number Generator.");
   printf("\n                0 (Standard C random function)");
   printf("\n	        1 (ISAAC RNG, default)");  
   printf("\n  -round nb: Complexity of the key generator process, default=2");
   printf("\n  -quiet   : Does not display any warning."); 
   printf("\n  -v       : Verbose mode."); 
   printf("\n  -ef file    : Redirect errors in a file (don't specify any filename\n                if you want it to be bpass.log)\n\n");
}
