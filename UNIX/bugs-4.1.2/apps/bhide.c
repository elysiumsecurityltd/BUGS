/*  
 *  bhide.c
 *
 *  Version 1.7
 *  03 October 2000 
 *
 *   HIDE FILE 
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
 * --- V 1.7 ---
 *
 * 03/10/2000:  - Added a '\0' after each strncpy as this is not done automatically
 *                on all OS.
 *
 *
 * --- V 1.6 ---
 *
 * 15/09/2000:  - Added the error output file option
 * 
 * --- V 1.5 ---
 *
 * 20/07/2000:  - Added new paramter to bcrypt_write_hide: varinit
 *                because I need to use it with bcrypt_fwrite_int()
 *
 *
 * --- V 1.4 ---
 *
 * 16/07/2000:  - Added a parameter to binit: RANDOM
 *		  which is set to any value you want, as it won't be used
 *		  in this appliciation
 *
 * 06/07/2000:  - Minor problem in the way I was allocating memory for
 *                the variables receiving the FILE NAMES.
 *                This could cause problem when using filename < 3
 *
 * --- V 1.3 ---
 *
 * 26/07/1999 : - Replaced sizeof() by strlen() while calling malloc()
 *
 * 23/07/1999 : - Changed the way I handle parameters
 *
 * --- V 1.2 ---
 * 
 * 16/02/1998 : - Corrected the input password bug
 *		- Changed bcrypt initialisation (binit)
 *
 * --- V 1.1 ---
 *
 * 07/02/1998 : - Minor changes about the informations displayed
 *		- Changed the default flag position to 1 (End of File)
 *              - Added the libcrypt version number
 *
 * --- V 1.0 --- 
 *
 * 27/01/1998 : - First tests
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

char *VERSION="v1.7, October 2000";

/*
 * Default : mode = 0 (non verbose)
 *           option = 1 (write at the end of file)
 */
  int MODE = 1;
  int PARAM_OPTION = 1;
  int PARAM_CHOICE = 0;
  char PARAM_SOURCE[200];
  char PARAM_DEST[200];
  char PARAM_ERRORFILE[200];
  int PARAM_ERROR = 0;
  globalvar *varinit;


/*
 * Functions
 */
void usage(void);
int init(void);
int hide(char **);
int argcheck(int, char **);


int 
main (int argc, char **argv)
{

if (argcheck(argc, argv) == 0) return 0;

if (init() == 0) return 0;

if (hide(argv) == 0) return 0;

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
binit(128, 1, PARAM_ERRORFILE, PARAM_ERROR, varinit);
return 1;
}


/*
 * Hide function 
 */
int hide(char **argv)
{

printf("\n BHIDE %s, Martinez Sylvain",VERSION);
printf("\n HIDE FILE");
printf("\n Libcrypt version : '%s'",varinit->LIB_VERSION);
printf("\n\n Source file : %s.",PARAM_SOURCE);
printf("\n Destination file : '%s'.",PARAM_DEST);
  
if (PARAM_CHOICE == 0)
   {
    printf("\n Hiding data in progress.\n");
    if (bcrypt_write_hide(PARAM_OPTION,PARAM_SOURCE,PARAM_DEST, varinit,MODE) == 0)
	{
	 printf("\n ERROR.");
	 printf("\n Writing hide file failed.\n\n");
         return 0;
	}
   }
else 
   {
    printf("\n Extracting hide data in progress.\n");
    if (bcrypt_read_hide(PARAM_OPTION, PARAM_SOURCE, PARAM_DEST, varinit, MODE) == 0)
       {
	 printf("\n ERROR.");
	 printf("\n Extracting hide data failed.\n\n");
         return 0;
	}
   }
printf("\n Operation finished.\n\n");
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
     if (0 == strcmp(argv[i],"-h")) PARAM_CHOICE = 0;    
     else if (0 == strcmp(argv[i],"-e")) PARAM_CHOICE = 1;
     else if ((0 == strcmp(argv[i],"-s")) && (i+1 < argc))
	     {
		if (strlen(argv[i+1]) >= 200)
                    {
                     printf("\n ERROR. \nSOURCE file name is too long. \n\n");
                     return 0;
                    }

		strcpy(PARAM_SOURCE,argv[i+1]);
		PARAM_SOURCE[strlen(argv[i+1])]='\0';
	     }
     else if ((0 == strcmp(argv[i],"-d")) && (i+1 < argc))
	     {
                if (strlen(argv[i+1]) >= 200)
                    {
                     printf("\n ERROR. \nDESTINATION file name is too long. \n\n");
                     return 0;
                    }
		strcpy(PARAM_DEST,argv[i+1]);
		PARAM_DEST[strlen(argv[i+1])]='\0';
	     }
     else if (0 == strcmp(argv[i],"-beg")) PARAM_OPTION = 0;
     else if (0 == strcmp(argv[i],"-end")) PARAM_OPTION = 1;
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
		strcpy(PARAM_ERRORFILE,"bhide.log");
                PARAM_ERRORFILE[strlen("bhide.log")]='\0';
		}
     
     
    }

if ((0 == strcmp(PARAM_SOURCE,"")) || (0 == strcmp(PARAM_DEST,"")))
   {
    usage();
    return 0;
   }

if (fopen(PARAM_SOURCE,"rb") == 0) 
{
 printf("\n ERROR.");
 printf("\n Source_file '%s' does not seems to exist.\n\n", PARAM_SOURCE);
 return 0;
}

if (0 == PARAM_CHOICE)
{
 if (fopen(PARAM_DEST,"rb") == 0) 
 {
  printf("\n ERROR.");
  printf("\n Dest_file '%s' does not seems to exist.\n\n",PARAM_DEST);
  return 0;
 }
}
else
{
 if (fopen(PARAM_DEST,"rb") != 0)
 {
  printf("\n ERROR.");
  printf("\n Dest_file '%s' ALREADY exists.\n\n",PARAM_DEST);
  return 0;
 }
}             

return 1;
}


void usage()
{
   printf("\n BHIDE %s, (C) Martinez Sylvain",VERSION);
   printf("\n HIDE FILE ");
   printf("\n\n Usage: bhide [MODE] -s SOURCE_FILE -d DEST_FILE {OPTIONS} [-v]");
   printf("\n\n [MODE] : "); 
   printf(" -h     : Hide source_file in dest_file (DEFAULT)");
   printf("\n           -e     : Extract hide data from source_file in dest_file");
   printf("\n\n {OPTIONS} : ");
   printf("\n\n  -beg   : Hide data at the begining of a file ");
   printf("\n\n  -end   : Hide data at the end of a file (DEFAULT)");
   printf("\n\n  -quiet : Does not display any warning.\n\n"); 
   printf("\n\n  -v     : Verbose mode."); 
   printf("\n  -ef file    : Redirect errors in a file (don't specify any filename\n                if you want it to be bhide.log)\n\n");   
}
