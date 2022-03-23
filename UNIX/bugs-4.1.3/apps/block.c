/*  
 *  block.c
 *
 *  Version 1.0
 *  11 November 2000 
 *
 *   FILE'S CRYPT PROGRAM
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
 * --- V 1.0 ---
 *
 * 11/11/2000:  - Change the default value of bcrypt_shuffle to sizeof(TYPE_INT)
 *
 * --- V 0.4 ---
 *
 * 03/10/2000:  - Added a '\0' after each strncpy as this is not done automatically
 *                on all OS.
 *
 * --- V 0.3 ---
 *
 * 15/09/2000:  - Added the error output file option
 * 
 * --- V 0.2 ---
 * 
 * 02/08/2000: - Changed the argcheck() to do not test argv[0] anymore
 *
 *              - Added '\0' in the PASSWORD string when sending a password
 *                as a parameter. On some system (ie. True64) the strncpy
 *                doesn't seem to add '\0' by default.                   
 *
 *
 * --- V 0.1  ---
 *
 * 30/07/2000:	- Created Application.
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

char *VERSION="v1.0, November 2000";


  /*
   * Default : mode = 0 (non verbose)
   *           Key's length = 128 bits
   *	       Power = 0
   *	       Key's file = 0
   */   

     int PARAM_CRYPT = 1;
     int MEMORY = 1;
     int ROUND = 2;
     int BLOCK_CRYPT = 0;
     int BLOCK_SHUFFLE = sizeof(TYPE_INT);
     int RANDOM = 1;
     char PARAM_SOURCE[200];
     char PARAM_TARGET[200];
     char PARAM_ERRORFILE[200];
     int PARAM_ERROR = 0;
     int PARAM_KEYLENGTH = 128;
     int PARAM_POWER = 4;
     int PARAM_VERBOSE = 0;   
     globalvar *varinit;
     char *PASSWORD;
     int PARAM_PASSWORD = 0;

void usage(void);
int init(void);
int crypt(void);
int argcheck(int, char **);

/*
 * Functions
 */

int main(int argc, char **argv)
{

    
  if (argcheck(argc, argv) == 0) return 0;

  if (init() == 0) return 0;

  if (crypt() == 0) return 0;
 
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
binit(PARAM_KEYLENGTH, RANDOM, PARAM_ERRORFILE, PARAM_ERROR, varinit);

return 1;
}

/*
 * Crypt file function
 */
int crypt()
{
  int i, crypt_time, length;
  char *pass_verif, carac, *tempname="";
  unsigned char *pass_clear;
  int status, RETURN=10;

pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);
pass_verif = (char *) malloc (varinit->NB_CHAR);

for(i=0; i < varinit->NB_CHAR; i++) pass_clear[i]='\0';
  
system("clear");
printf("\n Block %s, (C) Martinez Sylvain",VERSION);
printf("\n BUGS ALGORITHM LIGHT CRYPT FILE ");
printf("\n Libcrypt version : '%s'",varinit->LIB_VERSION);
printf("\n\n Crypt file in progress.");
printf("\n KEY'S LENGTH used : %d.",PARAM_KEYLENGTH);

    printf("\n Action            : CRYPT.");
   if (0 == PARAM_POWER)
       printf("\n Power             : (0) Seed only."); 
   if (1 == PARAM_POWER)
       printf("\n Power             : (1) Random Seed."); 
   if (2 == PARAM_POWER)
       printf("\n Power             : (2) Shuffle only."); 
   if (3 == PARAM_POWER)
       printf("\n Power             : (3) Seed and Shuffle."); 
   if (4 == PARAM_POWER)
       printf("\n Power             : (4) Random Seed and Shuffle."); 

   if (0 == RANDOM)
      printf("\n RNG               : (0) Standard C Algorithm.\n\n");
   if (1 == RANDOM)
      printf("\n RNG               : (1) ISAAC Algorithm.\n\n");

    tempname = (char *) malloc(strlen(PARAM_SOURCE)+10);
    strcpy(tempname, PARAM_SOURCE);

    strcat(tempname, ".bugsold");

	if(0 == PARAM_PASSWORD)
	 { 
          i=0;
          printf(" Password -> ");
          do{
             carac=bcrypt_vol(1);
             if(carac!=RETURN) pass_clear[i]=carac;
             i++;
            }while((i<varinit->NB_CHAR) && (carac!=RETURN));
         if (carac == RETURN)
            {
             pass_clear[i - 1]='\0';
             length = i - 1;
            }
         else
             length = i;
	  }
	 else
	  {
	   length = strlen(PASSWORD);
	   i=0;
	   do
	    {
		pass_clear[i] = PASSWORD[i];
		i++;
	    }while((i<length) && (i < varinit->NB_CHAR));

	  }

         if(length >= (varinit->NB_CHAR /2))
           {
            /*
             * We want to crypt
             */
		if (0 == PARAM_PASSWORD)
		{
               printf("\n Re-type Passwd -> ");
               i=0;
               do{
                  carac=bcrypt_vol(1);
                  if(carac!=RETURN) pass_verif[i]=carac;
                  i++;
                 }while((i<varinit->NB_CHAR) && (carac!=RETURN));
               
               if (carac == RETURN)
                  {
                   pass_verif[i - 1]='\0';
                   length = i - 1;
                  }
                else
                  length = i;
		}

        if ((1 == PARAM_PASSWORD) || (strcmp((char *) pass_clear,pass_verif)==0))
            {
             printf("\n Crypt started, Please Wait.\n");

		  strcpy(PARAM_TARGET,PARAM_SOURCE);
  		  printf(" '%s' renamed to '%s'.\n",PARAM_SOURCE, tempname);
		  rename(PARAM_SOURCE, tempname);

		 crypt_time = (int)(clock()/CLOCKS_PER_SEC);

                 if(bfile(0,tempname,PARAM_TARGET, "",pass_clear, length,
                    PARAM_POWER, ROUND, BLOCK_CRYPT, BLOCK_SHUFFLE, MEMORY, PARAM_VERBOSE, varinit) == 0)
                   {
                   printf("\n ERROR.\n");
                   return 0;
                   }

                  crypt_time = (int)(clock()/CLOCKS_PER_SEC) - crypt_time;

		  if (0 == strcmp(PARAM_SOURCE, PARAM_TARGET))
		  {
	           printf(" Removing temp file...\n");
	           remove(tempname);
		  }

                  printf("\n\n OK, File crypted in '%d' seconds ...\n", crypt_time);
                  return 1;
                  }
               else status=2;
               }
       else status=1;    
      
     if (status==1) printf("\n %d letters minimum and %d letters maximum ...\n",
                      (varinit->NB_CHAR/2), varinit->NB_CHAR);
     if (status==2) printf("\n You misspelled it. No file crypted.\n");
     return 0;
}


/*
 * Check the parameter of the program
 */
int argcheck(int argc, char **argv)
    {
	int i;
	FILE *temp_file;

	if (argc > 1)
	{
	 for (i = 1; i < argc; i++)
	 {
	
	 if ((strcmp(argv[i],"-pwd") == 0) && (i+1 < argc))
		{
		PASSWORD = (char *) malloc(strlen(argv[i+1]) + 1);
		strncpy(PASSWORD,argv[i+1],strlen(argv[i+1]));
		PASSWORD[strlen(argv[i+1])]='\0';
		PARAM_PASSWORD = 1;         
		 } 
	 else if (strcmp(argv[i],"-quiet") == 0) PARAM_VERBOSE=0;
	 else if (strcmp(argv[i],"-v") == 0) PARAM_VERBOSE=2;
	 else if (strcmp(argv[i],"-info") == 0) PARAM_VERBOSE=1;
	 else if (strcmp(argv[i],"-hd") == 0) MEMORY=0;
	 else if (strcmp(argv[i],"-help") == 0)
	         {
		  usage();
		  return 0;
              }
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
		strcpy(PARAM_ERRORFILE,"block.log");
                PARAM_ERRORFILE[strlen("block.log")]='\0';
		}
	 else 
            {
             strncpy(PARAM_SOURCE, argv[i],strlen(argv[i])%199);
             PARAM_SOURCE[(strlen(argv[i])%199)]='\0';
            }
         


	 }
    }	
   else
    {
	 usage();
	 return 0;
	}

if (0 == strcmp(PARAM_SOURCE,"")) 
   {
    usage();
    return 0;
   }

if ((temp_file=fopen(PARAM_SOURCE,"rb")) == 0) 
   {
    printf("\n ERROR.");
    printf("\n The file '%s' does not seem to exist.\n\n",PARAM_SOURCE);

    return 0;
    }
fclose(temp_file);

return 1;
}


void usage()
     {   
      printf("\n BLOCK %s, (C) Martinez Sylvain",VERSION);
      printf("\n BUGS ALGORITHM LIGHT CRYPT FILE");
      printf("\n\n Usage: block SOURCE_FILE {OPTIONS}");
      printf("\n\n  -help : Displays this help screen.");
      printf(" \n{OPTIONS}");
      printf("\n  -pwd passwd : Password you want to use to crypt/uncrypt (Not secure)");
      printf("\n  -hd         : Crypt directly to the disk (slow but uses less memory).");        
      printf("\n  -quiet      : Does not display warnings (Default)"); 
      printf("\n  -v          : Verbose mode. To redirect the output to a file add 2>filename"); 
      printf("\n  -info       : Display few information");
      printf("\n  -ef file    : Redirect errors in a file (don't specify any filename\n                if you want it to be block.log)\n\n");
     }        
