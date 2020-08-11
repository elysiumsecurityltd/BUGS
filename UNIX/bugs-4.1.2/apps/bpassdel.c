/*  
 *  bpassdel.c
 *
 *  Version 1.8
 *  26 July 2002 
 *
 *   DELETE USER AND PASSWORD FROM A PASSWORD DATABASE
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
 * 26/07/2002:  - I was not allowing any memory space for PARAM_USER nand 
 *                PARAM_FILE. Very stupid mistake.
 *
 * --- V 1.7 ---
 *
 * 03/10/2000:  - Added a '\0' after each strncpy as this is not done automatically
 *                on all OS.
 *
 * --- V 1.6 ---
 *
 * 15/09/2000:  - Added the error output file option
 *
 * --- V 1.5 ---
 *
 * 16/07/2000:  - Added a parameter to binit: RANDOM
 *		  which is set to any value you want, as it won't be used
 *		  in this appliciation
 *
 * 06/07/2000:  - Minor problem in the way I was allocating memory for
 *                the variables receiving the FILE NAMES.
 *                This could cause problem when using filename < 3
 *
 * --- V 1.4 ---
 *
 * 24/04/2000: - First implementation with the new library
 *
 * --- V 1.3 ---
 *
 * 26/07/1999 : - Replaced sizeof() by strlen() while calling malloc()
 *  
 * 23/07/1999 : - Changed the way I handle parameters
 *
 * 09/07/1999 : - Changed pass_clear from char to unsigned char
 *
 *  --- V 1.2 ---
 *
 * 16/02/1998 : - Corrected the input password bug
 *		- Changed bcrypt initialisation (binit)
 *
 * --- V 1.1 ---
 *
 * 07/02/1998 : - Added the libcrypt version number
 *
 * --- V 1.0 ---
 *
 * 27/01/1998 : - First tests.
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
#include "../include/misc.h" 
#include "../include/extra.h"

char *VERSION="v1.8, July 2002";

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
  char PARAM_USER[200];
  char PARAM_FILE[200];
  char PARAM_ERRORFILE[200];
  int PARAM_ERROR = 0;
  globalvar *varinit;

  
/*
 * Functions
 */
void usage(void);
int argcheck(int, char **);
int init(void);
int delete(char **);

int 
main (int argc, char **argv)
{

  if (argcheck(argc, argv) == 0) return 0;
  if (init() == 0) return 0;
  umask(077);
  if (delete(argv) == 0)
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
int delete(char **argv)
{
  char carac;
  int i, test, length;
  unsigned char *pass_clear;
  TYPE_INT *code_file;

  test = 1;

code_file = (TYPE_INT *) malloc(varinit->NB_CHAR);
pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);

printf("\n BPASSDEL %s, Martinez Sylvain",VERSION);
printf("\n DELETE PASSWORD"); 
printf("\n Libcrypt version : '%s'", varinit->LIB_VERSION);
printf("\n\n Delete Password in progress.");
printf("\n KEY'S LENGTH used : %d.",PARAM_KEY);
printf("\n Password file : '%s'.\n",PARAM_FILE);

  if (bcrypt_read_passwd ("root", PARAM_FILE, code_file, MODE, varinit) == 0)
    {
      printf ("\n Only the user 'root' can delete a passwd.");
      printf("\n This user MUST exist in the passwd file.\n\n");
      return 0;
    }


      printf ("\n Administrator identification : 'root' ");

      printf ("\n Root password -> ");
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

      if (blogin (code_file, pass_clear, length, 0, ROUND, MODE, varinit) == 0)
          {
	   printf("\n Identification failed. \n\n");
	   return 0;
          }
  /* 
   * Deleting passwd 
   */
      printf ("\n Are you sure to DELETE user '%s' [y/n] ", PARAM_USER);
      carac = bcrypt_vol(1);

      if (carac != 'y') 
         {
	  printf("\n Delete passwd canceled.\n\n");
	  return 0;
         }

     if(bcrypt_delete_passwd(PARAM_FILE, PARAM_USER, PARAM_KEY, MODE, varinit) == 0)
	{
	 printf("\n ERROR.");
	 printf("\n user '%s' may not exist.",PARAM_USER);
	 printf("\n Delete passwd failed.\n\n");
         return 0;
        }

  printf("\n user '%s' deleted.\n\n",PARAM_USER);
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
 * I give a default key length, but I will not use it.
 * Same for the Random value, set to 1, but which won't be used.
 */
binit(PARAM_KEY, 1, PARAM_ERRORFILE, PARAM_ERROR, varinit);
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
      if ((0 == strcmp(argv[i],"-f")) && (i+1 < argc))
	 {
                 if (strlen(argv[i+1]) >= 200)
                    {
                     printf("\n ERROR. \nPASSWORD file name is too long. \n\n");
                     return 0;
                    }
	  strcpy(PARAM_FILE,argv[i+1]);
          PARAM_FILE[strlen(argv[i+1])]='\0';
	 }
      else if ((0 == strcmp(argv[i],"-u")) && (i+1 < argc))
		{
                 if (strlen(argv[i+1]) >= 200)
                    {
                     printf("\n ERROR. \nUSER name is too long. \n\n");
                     return 0;
                    }
		 strcpy(PARAM_USER,argv[i+1]);
	         PARAM_USER[strlen(argv[i+1])]='\0';
		}
      else if ((0 == strcmp(argv[i],"-k")) && (i+1 < argc))
		{
		 PARAM_KEY = atoi(argv[i+1]);
		}
      else if ((0 == strcmp(argv[i],"-round")) && (i+1 < argc))
		{
		 ROUND = atoi(argv[i+1]);
		}
      else if (0 == strcmp(argv[i],"-quiet")) MODE = 0;
      else if (0 == strcmp(argv[i],"-v")) MODE = 2;
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
		strcpy(PARAM_ERRORFILE,"bpassdel.log");
                PARAM_ERRORFILE[strlen("bpassdel.log")]='\0';
		}
     }

if (0 == strcmp(PARAM_USER, ""))
   {
    usage();
    return 0;
   }

if (fopen(PARAM_FILE,"rb") == NULL) 
   {
    printf("\n ERROR.");
    printf("\n The file '%s' does not seem to exist.\n\n",PARAM_FILE);
    return 0;
   }
	
return 1;
}

void usage()
{
   printf("\n BPASSDEL %s, (C) Martinez Sylvain",VERSION);
   printf("\n DELETE PASSWORD AND USER"); 
   printf("\n\n Usage: bpassdel -f passwd_file -u user_name {OPTIONS}");
   printf("\n\n {OPTIONS} : ");
   printf("\n\n  -k nb    : KEYLENGTH which has to be a 2 multiple integer.");
   printf("\n             At least 32.");
   printf("\n             DEFAULT = 128"); 	
   printf("\n             Choose the same keylength that the one used to do the passwd");
   printf("\n  -round nb : Complexity of the key generator process, default=2");
   printf("\n  -quiet   : Does not display warning."); 
   printf("\n  -v : Verbose mode."); 
   printf("\n  -ef file    : Redirect errors in a file (don't specify any filename\n                if you want it to be bpassdel.log)\n\n");

}
