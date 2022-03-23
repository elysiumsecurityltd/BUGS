/*  
 *  bkey.c
 *
 *  Version 1.8
 *  03 October 2000 
 *
 *   KEYS GENERATOR 
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
 * --- V 1.8 ---
 *
 * 03/10/2000:  - Added a '\0' after each strncpy as this is not done automatically
 *                on all OS.
 *
 * --- V 1.7 ---
 *
 * 15/09/2000:  - Added the error output file option
 *
 * --- V 1.6 ---
 *
 * 16/07/2000:  - New option: RNG selector
 *		- Added a parameter to binit: RANDOM
 *
 * 06/07/2000:  - Minor problem in the way I was allocating memory for
 *                the variables receiving the FILE NAMES.
 *                This could cause problem when using filename < 3
 *
 * --- V 1.5 ---
 *
 * 24/04/2000 :	- First implementation with the new Library
 *
 * --- V 1.4 ---
 *
 * 26/07/1999 : - Replaced sizeof() by strlen() while calling malloc()
 *
 * 23/07/1999 : - Changed the way I handle the parameters
 *
 * 09/07/1999 : - Changed pass_clear from char to unsigned char
 *
 * --- V 1.3 ---
 * 
 * 15/02/1998 : - Corrected the input password bug
 *		- Changed bcrypt initialisation (binit)
 *
 * --- V 1.2 ---
 *
 * 07/02/1998 : - Added the libcrypt version number 
 *
 * --- V 1.1 ---
 *
 * 27/01/1998 : - Added some informations 
 *		- Cleaned the source code.	
 *
 * --- V 1.0 --- 
 *
 * 26/01/1998 : - First tests
 *
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
#include "../include/extra.h"

char *VERSION="v1.8, October 2000";

/*
   * Default : mode = 0 (non verbose)
   *           Key's length = 128 bits
   */
  int MODE = 1;
  int ROUND = 2;
  int PARAM_KEY = 128;
  int RANDOM = 1;
  int PARAM_RANDOM = 0;
  char PARAM_FILE[200];
  char PARAM_ERRORFILE[200];
  int PARAM_ERROR = 0;
  globalvar *varinit;

/*
 * ASCII code for the RETURN charactere that may change on different OS 
 */
const int BCRYPT_RETURN = 10;	


/*
 * Functions
 */
void usage(void);
int init(void);
int keygen(char **);
int argcheck(int, char **);

/*
 * I know, it is not good to do everything in the main function ...
 * That is just an example, that demonstrate my library
 * If you want something better, ask me !
 */
int 
main (int argc, char **argv)
{

if (argcheck(argc, argv) == 0) return 0;

if (init() == 0) return 0;
/*
 * The key file will have the following permissions:
 * rw-------
 */
umask(077);
if (keygen(argv) == 0)
{
 umask(002);
 return 0;
}
umask(002);

return 1;
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
 * Key generation
 */
int keygen(char **argv)
{
  char carac;
  unsigned char *pass_clear;
  int length=0, i;

pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);

printf("\n BKEYGEN %s, Martinez Sylvain",VERSION);
printf("\n BUGS ALGORITHM KEY GENERATOR");
printf("\n Libcrypt version : '%s'",varinit->LIB_VERSION);
printf("\n\n KEY'S LENGTH : %d.",PARAM_KEY);
printf("\n KEY file : '%s'.\n",PARAM_FILE);

  /* 
   * Changing passwd 
   */
  if (PARAM_RANDOM == 0)
    {
      i = 0;
      printf ("\n Enter characters [8..16] -> ");
      do
	{
	  carac = bcrypt_vol (1);
	  if (carac != BCRYPT_RETURN) pass_clear[i] = carac;
	  i++;
	}
      while ((i < 16) && (carac != BCRYPT_RETURN));
      if (i < 8)
	 {
	  printf("\n ERROR.");
	  printf("\n 8 characters minimum.\n\n");
  	  return 0;
         }

       if(carac == BCRYPT_RETURN)
        {
	pass_clear[i - 1] = '\0';
        length = i - 1;
        }
        else 
          length = i;

    }
    else
     printf("\n Random initialisation.\n");

     printf("\n Key generation in progress.\n");        
     if (bkey_generator (pass_clear, length, ROUND, PARAM_FILE, 0, PARAM_RANDOM, MODE,
         varinit) == 0)
 	{
	 printf("\n ERROR.");
	 printf("\n Key generation failed.\n\n");
        }

      printf("\n Key's generation done.\n\n");

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
	if (0 == strcmp(argv[i],"-auto"))   PARAM_RANDOM = 1;
        else if (0 == strcmp(argv[i],"-pass"))  PARAM_RANDOM = 0;
	else if ((0 == strcmp(argv[i],"-f")) && (i+1 < argc))	
	   {
                 if (strlen(argv[i+1]) >= 200)
                    {
                     printf("\n ERROR. \nKEY file name is too long. \n\n");
                     return 0;
                    }
	    strcpy(PARAM_FILE, argv[i+1]);
	    PARAM_FILE[strlen(argv[i+1])]='\0';
	   }
	else if ((0 == strcmp(argv[i],"-k")) && (i+1 < argc)) PARAM_KEY = atoi(argv[i+1]);
        else if ((strcmp(argv[i],"-r") == 0) && (i+1 < argc)) RANDOM=atoi(argv[i+1]);
	else if ((0 == strcmp(argv[i],"-round")) && (i+1 < argc)) ROUND = atoi(argv[i+1]);
	else if (0 == strcmp(argv[i],"-v")) MODE = 2;
	else if (0 == strcmp(argv[i],"-quiet")) MODE = 0;
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
		strcpy(PARAM_ERRORFILE,"bkey.log");
                PARAM_ERRORFILE[strlen("bkey.log")]='\0';
		}
      }
   
if (0 == strcmp(PARAM_FILE,""))
   {
    usage();
    return 0;
   }

if (fopen(PARAM_FILE,"rb") != 0) 
   {
    printf("\n ERROR.");
    printf("\n The file '%s' already exist.\n\n",argv[2]);
    return 0;
    }

if (PARAM_KEY < 128)
   {
    printf("\n ERROR.");
    printf("\n You can only generate key > 128 bits.\n\n");
    return 0;
   }

return 1;
}


void usage()
{
   printf("\n BKEYGEN %s, (C) Martinez Sylvain",VERSION);
   printf("\n BUGS ALGORITHM KEY GENERATOR");
   printf("\n\n Usage: bkeygen [MODE] -f key_store_file {OPTIONS} ");
   printf("\n\n [MODE] : "); 
   printf(" -auto     : Generate a key from a RANDOM SEQUENCE");
   printf("\n 	   -pass     : Generate a key from a 128 bits length password (DEFAULT)");
   printf("\n\n {OPTIONS} : ");
   printf("\n -k nb   : KEYLENGTH which has to be a 2 multiple integer.");
   printf("\n	        At least 128.");
   printf("\n	        DEFAULT = 128"); 
   printf("\n  -r nb       : Random Number Generator.");
   printf("\n                0 (Standard C random function)");
   printf("\n	        1 (ISAAC RNG, default)");  
   printf("\n\n  -round nb: Complexity of the key generator process, default=2"); 	
   printf("\n\n  -quiet : Does not display any warning."); 
   printf("\n\n  -v     : Verbose mode.");
   printf("\n  -ef file    : Redirect errors in a file (don't specify any filename\n                if you want it to be bkey.log)\n\n"); 
}
