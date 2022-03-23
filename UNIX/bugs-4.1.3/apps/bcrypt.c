/*  
 *  bcrypt.c
 *
 *  Version 3.4
 *  16 November 2000 
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
 * --- V 3.4 ---
 *
 * 19/11/2000:  - Minor changes in order to use block crypt >= 1
 *                when using power 0 or 1
 *
 * 16/11/2000:  - The quiet mode is ... really quiet now ! ;o)
 *
 * 11/11/2000:  - Added BSSL options
 *
 * 08/11/2000:  - Added new library options (Dynamic options).
 *              - Corrected a problem with block_shuffle and block_crypt in
 *                the interactive mode.
 *              - Change the default value of bcrypt_shuffle to sizeof(TYPE_INT)
 *
 * --- V 3.3 ---
 *
 * 03/10/2000:  - Added '\0' after each strncpy as this is not done automatically
 *                on all OS.
 *
 * --- V 3.2 ---
 *
 * 01/10/2000:  - Added the -a option to crypt/decrypt in ASCII mode
 *
 * --- V 3.1 ---
 *
 * 26/09/2000:  - Corrected a minor error when prompted to enter the 
 *                complexity value in the Interactive mode
 *
 *              - Corrected a MAJOR error in the interactive mode.
 *                The new keylength, random and log values were not
 *                activated as I was not calling binit() again !
 *                Stupid thing !
 *
 * --- V 3.0 --- 
 *
 * 17/09/2000:  - There is now an interactive mode letting that prompt
 *                for all the parameters
 *
 * --- V 2.7 ---
 *
 * 15/09/2000:  - Added the error output file option
 *
 * --- V 2.6 ---
 * 
 * 02/08/2000:  - Added '\0' in the PASSWORD string when sending a password
 *                as a parameter. On some system (ie. True64) the strncpy
 *                doesn't seem to add '\0' by default.
 * 
 * --- V 2.5 ---
 *
 * 30/07/2000:  - Added a system("clear") at the start of the application
 *
 * --- V 2.4 ---
 *
 * 17/07/2000:	- Corrected minor error in the display while UNcrypting
 *
 * --- V 2.3 ---
 *
 * 16/07/2000:  - Changed the way I was calling binit, now there is a new
 *		  Parameter: RANDOM
 *		- Added a new parameter: -pwd  youcan now send your password 
 *		  as a parameter.
 *
 * 
 * 13/07/2000:  - Added random choice parameter
 *
 *
 * 05/07/2000:	- Minor problem in the way I was allocating memory for
 *		  the variables receiving the FILE NAMES.
 *		  This could cause problem when using filename < 3
 *
 * --- V 2.2 ---
 *
 * 18/05/2000:  - Remove obsolet parameter checks
 * 		- Power 4 is now the default power level
 * 		- Minor changes in the output information
 * 
 * 24/04/2000:	- Changed some parameters: -quiet and -v
 *		- Added -comp parameter
 *
 * 15/03/2000:  - Added some parameter: 
 *		  bc = block crypt
 *		  bs = block shuffle
 *
 * 04/02/2000:  - Added 2 parameters: 
 *		  debug = set MODE to 2
 *		  hd = set MEMORY to 0
 *
 * 17/01/2000:  - First test with the new library
 *
 * --- V 2.1 ---
 *
 * 01/11/1999 : - Minor bug corrected, the verbose mode was not working 
 *		  if you were using "-v" as the last argument.
 *
 * 01/11/1999 : - Something really weird... If the character's length of 
 *		  a filepath is 44 and there is a space in it, strcpy
 *	          seems to copy to many characters, strncpy doesn't work 
 *		  either ! 
 *		  I had to change the way I was initialising the array
 *		  instead of doing malloc(strlen(argv[i+1]) I am doing
 *		  malloc(strlen(argv[i+1]) + 1) 
 *		  After Many tests it seems because strcpy adds /0 at the end 
 *		  why then this is not happening if the length is not 44 ??
 *		  It sounds like a memory handling problem, but I checked
 *		  evreything and did not find any problems...
 *		  If someone have any ideas, let me know ! :O)
 *
 * 31/10/1999 : - Removed a dummy "printf" only used in testing
 *
 * --- V 2.0 ---
 *
 * 24/07/1999 : - Replaced sizeof() by strlen when calling malloc()
 *		- Corrected a problem while overwriting the source file
 *
 * 23/07/1999 : - Added a check in the checkargs()
 *		- Corrected a malloc problem with PARAM_KEYFILE
 *
 * 22/07/1999 : - Corrected errors while crypting with a keyfile
 *		  This was caused by the way I was overwriting files 
 *		- Corrected an error while uncrypting with a keyfile
 *		  This was because I didn't initialised the length var.
 *		  Added: length=varinit->NB_CHAR;
 *
 * 20/07/1999 : - Changed the way I handle parameters, much more efficient 
 *		- You can now overwrite a file you crypt.
 *
 * 09/07/1999 : - Changed pass_clear from char to unsigned char
 *
 * --- V 1.7 ---
 *
 * 16/02/1998 : - Corrected the input password bug
 *		- Changed bcrypt initialisation (binit)
 *
 * --- V 1.6 ---
 *
 * 07/02/1998 : - Added the libcrypt version number
 *
 * --- V 1.5 ---
 *
 * 27/01/1998 : - Added the -f option
 *	        - cleaned the source code, everything is not anymore
 *		  in the main() function !
 *
 * ---- V 1.4 ----
 *
 * 13/01/1998 : - Added globalvar type variable
 *
 * 11/01/1998 : - Added global variable VERSION
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
#include "../include/extra.h"

char *VERSION="v3.4, November 2000";

  /*
   * Default : mode = 0 (non verbose)
   *           Key's length = 128 bits
   *	       Power = 0
   *	       Key's file = 0
   */   

     int PARAM_CRYPT = 0;
     int PARAM_UNCRYPT = 0;
     int MEMORY = 1;
     int ROUND = 2;
     int BLOCK_CRYPT = 0;
     int BLOCK_SHUFFLE = sizeof(TYPE_INT);
     int KEY_BUFFER = 16;
     int DROUND = 1;
     int DSWAP = 1;
     int DSHUFFLE = 1;
     int DBUFFER = 1;
     int RANDOM = 1;
     int BSSL = 0;
     char PARAM_SOURCE[200];
     char PARAM_TARGET[200];
     char PARAM_KEYFILE[200];
     char PARAM_ERRORFILE[200];
     int PARAM_ERROR = 0;
     int PARAM_KEYLENGTH = 128;
     int PARAM_POWER = 4;
     int PARAM_VERBOSE = 1;   
     globalvar *varinit;
     char *PASSWORD;
     int PARAM_PASSWORD = 0;
     int OPTION;
     int INTERACTIVE = 0;
     int PARAM_ASCII = 0;

void usage(void);
void options(void);
int init(void);
int crypt(void);
int argcheck(int, char **);
int validation(void);
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
  int i, j, crypt_time, length;
  char *pass_verif, carac, *tempname="";
  unsigned char *pass_clear;
  int status, RETURN=10;
  int choice = 0;
  int temp_power;

pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);
pass_verif = (char *) malloc (varinit->NB_CHAR);

temp_power = PARAM_POWER;

for(i=0; i < varinit->NB_CHAR; i++) pass_clear[i]='\0';
  
if (0 != PARAM_VERBOSE)
 system("clear");

if (0 != PARAM_VERBOSE)
{
printf("\n Bcrypt %s, (C) Martinez Sylvain",VERSION);
printf("\n BUGS ALGORITHM CRYPT FILE ");
printf("\n Libcrypt version : '%s'",varinit->LIB_VERSION);
printf("\n\n Crypt file in progress.");
}

if (1 == INTERACTIVE)
{
printf("\n\n -- INTERACTIVE MODE --\n"); 


BSSL = -1;
while(BSSL < 0)
{
printf("\n -> Use Preset BSSL [Y]es/[N]o (N)? ");
carac = bcrypt_vol(1);
if( (carac == 'y') || (carac == 'Y')) 
  {
   BSSL = 30;
   printf("\n    .Using BSSL");
  }
else if( (carac == 'n') || (carac == 'N')) 
  {
   BSSL = 0;
   printf("\n    .Not using BSSL");
  }
  
if (carac == RETURN)
  {
   BSSL = 0;
   printf("\n    .Not using BSSL");
  }
}


if (0 != BSSL)
{
 BSSL = -1;
 while((BSSL < 0) || (BSSL > BSSL_VHIGH))
{
printf("\n -> BSSL Level [(1) Very Low ]");
printf("\n               [(2) Low      ]");
printf("\n               [(3) Medium   ]");
printf("\n               [(4) High     ]");
printf("\n               [(5) Very High]");
printf("\n               ---------------> (3) ? ");
carac = bcrypt_vol(1);

BSSL=atoi(&carac);

if (carac == RETURN)
  {
   BSSL = 3;
  }
}
    printf("\n   .BSSL Level is ");

  if (1 == BSSL)
    printf("Very Low");

  if (2 == BSSL)
    printf("Low");

  if (3 == BSSL)
    printf("Medium");

  if (4 == BSSL)
    printf("High");

  if (5 == BSSL)
    printf("Very High");

}

else
{
PARAM_KEYLENGTH = -1;
while(PARAM_KEYLENGTH <= 0)
{
printf("\n -> Keylength (128)? ");

PARAM_KEYLENGTH=0;
i=0;
   do{
             carac=bcrypt_vol(1);
             if(carac!=RETURN) 
               {
                PARAM_KEYLENGTH = (PARAM_KEYLENGTH * 10) + atoi(&carac);
                printf("%c",carac);
               }
             
             i++;
            }while((i<50) && (carac!=RETURN));

if ( (1 == i) && (carac == RETURN)) PARAM_KEYLENGTH = 128;

printf("\n    .Keylength is %d", PARAM_KEYLENGTH);
  
}

}

PARAM_CRYPT = -1;
while(PARAM_CRYPT < 0)
{
printf("\n -> Action [C]rypt/[D]ecrypt (C)?");
carac = bcrypt_vol(1);
if( (carac == 'c') || (carac == 'C')) 
  {
   PARAM_CRYPT = 1;
   PARAM_UNCRYPT = 0;
   printf("\n   .Crypt selected");
  }
else if( (carac == 'd') || (carac == 'D')) 
  {
   PARAM_CRYPT = 0;
   PARAM_UNCRYPT = 1;
   printf("\n    .Decrypt selected");
  }
  
if (carac == RETURN)
  {
   PARAM_CRYPT = 1;
   PARAM_UNCRYPT = 0;
   printf("\n   .Crypt selected");
  }
}

printf("\n -> Source filename ? ");
i=0;
   do{
             carac=bcrypt_vol(1);
             if(carac!=RETURN) 
               {
                PARAM_SOURCE[i]=carac;
                printf("%c",carac);
               }
             
             i++;
            }while((i<200) && (carac!=RETURN));
         if (carac == RETURN)
             PARAM_SOURCE[i - 1]='\0';

printf("\n    .Source is %s", PARAM_SOURCE);

printf("\n -> Destination filename (press ENTER = same as source file)? ");
i=0;
   do{
             carac=bcrypt_vol(1);
             if(carac!=RETURN) 
               {
                PARAM_TARGET[i]=carac;
                printf("%c",carac);
               }
             
             i++;
            }while((i<200) && (carac!=RETURN));
         if (carac == RETURN)
             PARAM_TARGET[i - 1]='\0';

if (0 == strcmp(PARAM_TARGET,""))
    printf("\n    .Destination is %s", PARAM_SOURCE);
else
    printf("\n    .Destination is %s", PARAM_TARGET);

j = -1;
while(j < 0)
{
printf("\n -> Password or Keyfile [P/K] (P)?");
carac = bcrypt_vol(1);
if( (carac == 'k') || (carac == 'K')) 
  {
   printf("\n -> Keyfile filename ? ");
   i=0;
   do{
             carac=bcrypt_vol(1);
             if(carac!=RETURN) 
               {
                PARAM_KEYFILE[i]=carac;
                printf("%c",carac);
               }
             
             i++;
       }while((i<200) && (carac!=RETURN));
    if (carac == RETURN)
       PARAM_KEYFILE[i - 1]='\0';

    printf("\n    .Keyfile is %s", PARAM_KEYFILE);
    j = 0;

  }
else 
  {

   if( (carac == 'p') || (carac == 'P')) 
   {
    j = 0;
    printf("\n    .Password selected");
   }


  if (carac == RETURN)
   {
    j = 0;
    printf("\n   .Password selected");
   }
 }

}


PARAM_ASCII = -1;
while(PARAM_ASCII < 0)
{
printf("\n -> Use/Produce a cipher file in [B]inary/[A]scii (B)?");
carac = bcrypt_vol(1);
if( (carac == 'b') || (carac == 'B')) 
  {
   PARAM_ASCII = 0;
   printf("\n   .Binary mode selected");
  }
else if( (carac == 'a') || (carac == 'A')) 
  {
   PARAM_ASCII = 1;
   printf("\n    .Ascii mode selected");
  }
  
if (carac == RETURN)
  {
   PARAM_ASCII = 0;
   printf("\n   .Binary mode selected");
  }
}



if (0 == BSSL)
{
PARAM_POWER = -1;
while((PARAM_POWER < 0) || (PARAM_POWER > 4))
{
printf("\n -> Power [0 -> 4] (4)?");
carac = bcrypt_vol(1);

PARAM_POWER=atoi(&carac);

if (carac == RETURN)
  {
   PARAM_POWER = 4;
  }
}
    printf("\n   .Power is %d",PARAM_POWER);


}

PARAM_VERBOSE = -1;
while((PARAM_VERBOSE < 0) || (PARAM_VERBOSE > 2))
{
printf("\n -> Verbose Level [0/1/2] (1)?");
carac = bcrypt_vol(1);

PARAM_VERBOSE=atoi(&carac);

if (carac == RETURN)
  {
   PARAM_VERBOSE = 1;
  }
}
    printf("\n   .Verbose Level is %d",PARAM_VERBOSE);



j = -1;
while(j < 0)
{
printf("\n -> Advanced Options [Y/N] (N)?");
carac = bcrypt_vol(1);
if( (carac == 'y') || (carac == 'Y')) 
  {
  
RANDOM = -1;
while((RANDOM < 0) || (RANDOM > 1))
{
printf("\n -> Random Algorithm [Standard(0)/ISAAC(1)] (1)?");
carac = bcrypt_vol(1);

RANDOM=atoi(&carac);

if (carac == RETURN)
  {
   RANDOM = 1;
  }
}
    if (1 == RANDOM)
	    printf("\n   .Random Algorithm is ISAAC");
    else
	    printf("\n   .Random Algorithm is Standard");


ROUND = -1;
while(ROUND < 0)
{
printf("\n -> Nb of Round (2)? ");

   i=0;
   ROUND = 0;
   do{
             carac=bcrypt_vol(1);
             if(carac!=RETURN) 
               {
                ROUND = (ROUND * 10) + atoi(&carac);
                printf("%c",carac);
               }
             
             i++;
      }while((i<10) && (carac!=RETURN));

    if ( (1 == i) && (carac == RETURN)) ROUND = 2;

}

   printf("\n   .Nb of round is %d", ROUND);



BLOCK_CRYPT = -1;
while(BLOCK_CRYPT < 0)
{
printf("\n -> Block Crypt (0)? ");

   i=0;
   BLOCK_CRYPT = 0;
   do{
             carac=bcrypt_vol(1);
             if(carac!=RETURN) 
               {
                BLOCK_CRYPT = (BLOCK_CRYPT * 10) + atoi(&carac);
                printf("%c",carac);
               }
             
             i++;
      }while((i<10) && (carac!=RETURN));

    if ( (1 == i) && (carac == RETURN)) BLOCK_CRYPT = 0;

}

    printf("\n   .Block Crypt is %d", BLOCK_CRYPT);


BLOCK_SHUFFLE = -1;
while(BLOCK_SHUFFLE < 0)
{
printf("\n -> Block Shuffle (%d)? ", sizeof(TYPE_INT));

   i=0;
   BLOCK_SHUFFLE = 0;
   do{
             carac=bcrypt_vol(1);
             if(carac!=RETURN) 
               {
                BLOCK_SHUFFLE = (BLOCK_SHUFFLE * 10) + atoi(&carac);
                printf("%c",carac);
               }
             
             i++;
      }while((i<10) && (carac!=RETURN));

    if ( (1 == i) && (carac == RETURN)) BLOCK_SHUFFLE = sizeof(TYPE_INT);

}

    printf("\n   .Block Shuffle is %d", BLOCK_SHUFFLE);


if (0 == BSSL)
{
KEY_BUFFER = -1;
while(KEY_BUFFER < 0)
{
printf("\n -> Nb of Key Buffer (16)? ");

KEY_BUFFER = 0;

 i=0;
  do{
     carac=bcrypt_vol(1);
     if(carac!=RETURN) 
      {
        KEY_BUFFER = (KEY_BUFFER * 10) + atoi(&carac);
        printf("%c",carac);
      }
             
     i++;
    }while((i<50) && (carac!=RETURN));

 if ( (1 == i) && (carac == RETURN)) KEY_BUFFER = 16;

}

printf("\n   .Nb of Key Buffer is %d", KEY_BUFFER);
}


MEMORY = -1;
while((MEMORY < 0) || (MEMORY > 1))
{
printf("\n -> Buffer Method [(M)emory/(H)arddisk] (M)?");
carac = bcrypt_vol(1);
if( (carac == 'm') || (carac == 'M')) 
  {
   MEMORY = 1;
   printf("\n   .Memory Buffer selected");
  }
else if( (carac == 'h') || (carac == 'H')) 
  {
   MEMORY = 0;
   printf("\n    .Hard Disk Buffer selected");
  }
  
if (carac == RETURN)
  {
   MEMORY = 1;
   printf("\n   .Memory Buffer selected");
  }
}


if (0 == BSSL)
{
DROUND = -1;
while((DROUND < 0) || (DROUND > 1))
{
printf("\n -> Dynamic Round [(Y)es/(N)o] (Y)?");
carac = bcrypt_vol(1);
if( (carac == 'y') || (carac == 'Y')) 
  {
   DROUND = 1;
   printf("\n   .Dynamic Round selected");
  }
else if( (carac == 'n') || (carac == 'N')) 
  {
   DROUND = 0;
   printf("\n    .NO Dynamic Round.");
  }
  
if (carac == RETURN)
  {
   DROUND = 1;
   printf("\n   .Dynamic Round selected");
  }
}

DSWAP = -1;
while((DSWAP < 0) || (DSWAP > 1))
{
printf("\n -> Dynamic Modulo Swap [(Y)es/(N)o] (Y)?");
carac = bcrypt_vol(1);
if( (carac == 'y') || (carac == 'Y')) 
  {
   DSWAP = 1;
   printf("\n   .Dynamic Modulo Swap selected");
  }
else if( (carac == 'n') || (carac == 'N')) 
  {
   DSWAP = 0;
   printf("\n    .NO Dynamic Modulo Swap.");
  }
  
if (carac == RETURN)
  {
   DSWAP = 1;
   printf("\n   .Dynamic Modulo Swap selected");
  }
}


DSHUFFLE = -1;
while((DSHUFFLE < 0) || (DSHUFFLE > 1))
{
printf("\n -> Dynamic Block Shuffle [(Y)es/(N)o] (Y)?");
carac = bcrypt_vol(1);
if( (carac == 'y') || (carac == 'Y')) 
  {
   DSHUFFLE = 1;
   printf("\n   .Dynamic Block Shuffle selected");
  }
else if( (carac == 'n') || (carac == 'N')) 
  {
   DSHUFFLE = 0;
   printf("\n    .NO Dynamic Block Shuffle.");
  }
  
if (carac == RETURN)
  {
   DSHUFFLE = 1;
   printf("\n   .Dynamic Block Shuffle selected");
  }
}

DBUFFER = -1;
while((DBUFFER < 0) || (DBUFFER > 1))
{
printf("\n -> Dynamic Key Buffer [(Y)es/(N)o] (Y)?");
carac = bcrypt_vol(1);
if( (carac == 'y') || (carac == 'Y')) 
  {
   DBUFFER = 1;
   printf("\n   .Dynamic Key Buffer selected");
  }
else if( (carac == 'n') || (carac == 'N')) 
  {
   DBUFFER = 0;
   printf("\n    .NO Dynamic Key Buffer.");
  }
  
if (carac == RETURN)
  {
   DBUFFER = 1;
   printf("\n   .Dynamic Key Buffer selected");
  }
}
}

j = -1;
while(j < 0)
{
printf("\n -> Error Log Output [(S)tandard error/(F)ile? (S)");
carac = bcrypt_vol(1);
if( (carac == 'f') || (carac == 'F')) 
  {
   printf("\n -> Error Log output filename ? ");
   i=0;
   do{
             carac=bcrypt_vol(1);
             if(carac!=RETURN) 
               {
                PARAM_ERRORFILE[i]=carac;
                printf("%c",carac);
               }
             
             i++;
       }while((i<200) && (carac!=RETURN));
    if (carac == RETURN)
       PARAM_ERRORFILE[i - 1]='\0';

    PARAM_ERROR = 1;
    printf("\n    .Error Log output file is %s", PARAM_ERRORFILE);
    j = 0;

  }
else 
  {

   if( (carac == 's') || (carac == 'S')) 
   {
    j = 0;
    printf("\n    .Standard Error output selected");
    PARAM_ERROR = 0;
   }


  if (carac == RETURN)
   {
    j = 0;
    printf("\n    .Standard Error output selected");
    PARAM_ERROR = 0;
   }
 }

}




  }
else 
  {

   if( (carac == 'n') || (carac == 'N')) 
   {
    j = 0;
    printf("\n    .No Advanced Options");
   }


  if (carac == RETURN)
   {
    j = 0;
    printf("\n   .No Advanced Options");
   }
 }



}



}




 if (0 == validation())
    {
     printf("\n Error while trying to validate the parameters\n\n");
     return 0;
    }


if (1 == INTERACTIVE)
	binit(PARAM_KEYLENGTH, RANDOM, PARAM_ERRORFILE, PARAM_ERROR, varinit);

if (0 != PARAM_VERBOSE)
 { 
  if (1 == PARAM_CRYPT)
   printf("\n Action            : CRYPT.");
  else
   printf("\n Action            : UNCRYPT.");
 }


if (0 == BSSL)
 {
  varinit->MISC = 0;


if (1 == DROUND)
  varinit->MISC ^= BMASK_ROUND;

if (1 == DSWAP)
  varinit->MISC ^= BMASK_SWAP;

if (1 == DSHUFFLE)
  varinit->MISC ^= BMASK_SHUFFLE;

if (1 == DBUFFER)
  varinit->MISC ^= BMASK_BUFFER;

varinit->KEY_BUFFER = KEY_BUFFER;
}
else
 {
  temp_power=bssl(BSSL, &ROUND, &BLOCK_CRYPT, &BLOCK_SHUFFLE, varinit,PARAM_VERBOSE);
  if (0 < temp_power)
   PARAM_POWER = temp_power;
 }
 PARAM_KEYLENGTH = varinit->KEYLENGTH;

if (0 != PARAM_VERBOSE)
{
 printf("\n KEY'S LENGTH used : %d.",PARAM_KEYLENGTH);

if (BMASK_ROUND ==  (varinit->MISC & BMASK_ROUND))
  printf("\n Dynamic Round     : Yes.");
else
  printf("\n Dynamic Round     : No.");

if (BMASK_SWAP  ==   (varinit->MISC & BMASK_SWAP))
  printf("\n Dynamic Swap      : Yes.");
else
  printf("\n Dynamic Swap      : No.");

if (BMASK_SHUFFLE ==  (varinit->MISC & BMASK_SHUFFLE))
  printf("\n Dynamic Shuffle   : Yes.");
else
  printf("\n Dynamic Shuffle   : No.");

if (BMASK_BUFFER == (varinit->MISC & BMASK_BUFFER))
  printf("\n Dynamic Buffer    : Yes.");
else
  printf("\n Dynamic Buffer    : No.");

printf("\n Nb of Key Buffer  : %d.",varinit->KEY_BUFFER);


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
    printf("\n RNG               : (0) Standard C Algorithm.");
 if (1 == RANDOM)
    printf("\n RNG               : (1) ISAAC Algorithm.");
}

if (1 == PARAM_CRYPT)
   {
    if (1 == PARAM_ASCII) choice = 2;
    else
      choice = 0;

    tempname = (char *) malloc(strlen(PARAM_SOURCE)+10);
    strcpy(tempname, PARAM_SOURCE);

    if (0 == strcmp(PARAM_TARGET, PARAM_SOURCE))
       {
        strcat(tempname, ".bugsold");
       }

	if (0 != PARAM_VERBOSE)
	{
    	if (0 != strcmp(PARAM_KEYFILE, ""))
		{
		 printf("\n Key File          : '%s'.",PARAM_KEYFILE);
		}
   	 printf("\n Clear file        : '%s'.",PARAM_SOURCE);
   	 if (0 == strcmp(PARAM_SOURCE, PARAM_TARGET)) printf("\n Temp file : '%s'.",tempname);
   	 printf("\n Cipher file       : '%s'.\n\n",PARAM_TARGET);
	}
   }
else 
   {

    if (1 == PARAM_ASCII) choice = 3;
    else
      choice = 1;

	if (0 != PARAM_VERBOSE)
	{

 	   if (0 != strcmp(PARAM_KEYFILE, ""))
		{
		 printf("\n Key File : '%s'.",PARAM_KEYFILE);
		}
   	 printf("\n Cipher file       : '%s'.",PARAM_SOURCE);
    	printf("\n Clear file        : '%s'.\n\n",PARAM_TARGET);
       }
   }

if (0 == strcmp(PARAM_KEYFILE,""))
   {
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
            if (1 == PARAM_CRYPT)            
               {
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
			if (0 != PARAM_VERBOSE)
                 	printf("\n Crypt started, Please Wait.\n");

		 if (0 == strcmp(PARAM_SOURCE, PARAM_TARGET))
		 {
		  if (0 != PARAM_VERBOSE)
  		   printf(" '%s' renamed to '%s'.\n",PARAM_SOURCE, tempname);
		  rename(PARAM_SOURCE, tempname);
		 }

		 crypt_time = (int)(clock()/CLOCKS_PER_SEC);



                 if(bfile(choice,tempname,PARAM_TARGET, "",pass_clear, length,
                    PARAM_POWER, ROUND, BLOCK_CRYPT, BLOCK_SHUFFLE, MEMORY, PARAM_VERBOSE, varinit) == 0)
                   {
                   printf("\n ERROR.\n");
                   return 0;
                   }

                  crypt_time = (int)(clock()/CLOCKS_PER_SEC) - crypt_time;

		  if (0 == strcmp(PARAM_SOURCE, PARAM_TARGET))
		  {
                   if (0 != PARAM_VERBOSE)
	            printf(" Removing temp file...\n");
	           remove(tempname);
		  }
                  if (0 != PARAM_VERBOSE)
                   printf("\n\n OK, File crypted in '%d' seconds ...\n", crypt_time);
                  return 1;
                  }
               else status=2;
               }
           /* 
            * We want to uncrypt
            */
           else   
            {
            if (0 != PARAM_VERBOSE)
             printf("\n Uncrypt started, Please Wait.\n");
            crypt_time = (int)(clock()/CLOCKS_PER_SEC);

            if (bfile(choice,PARAM_SOURCE, PARAM_TARGET,"" ,pass_clear, length,
                PARAM_POWER, ROUND, BLOCK_CRYPT, BLOCK_SHUFFLE, MEMORY, PARAM_VERBOSE, varinit)==0)
               {
                printf("\n ERROR.\n");
                return 0;
               }
            crypt_time = (int)(clock()/CLOCKS_PER_SEC) - crypt_time;

            if (0 != PARAM_VERBOSE)
             printf("\n\n OK, File UNcrypted in '%d' seconds ...\n", crypt_time); 
             return 1;
            }

       }
       else status=1;    
      
     if (status==1) printf("\n %d letters minimum and %d letters maximum ...\n",
                      (varinit->NB_CHAR/2), varinit->NB_CHAR);
     if (status==2) printf("\n You misspelled it. No file crypted.\n");
     return 0;
    }
   else
     {
        if (1 == PARAM_CRYPT)   
            {
            length = varinit->NB_CHAR;
            printf("\n Crypt started, Please Wait.\n");

	    if (0 == strcmp(PARAM_SOURCE,PARAM_TARGET))
	    {
 	     printf(" '%s' renamed to '%s'.\n",PARAM_SOURCE, tempname);
	     rename(PARAM_SOURCE, tempname);
	    }
            crypt_time = (int)(clock()/CLOCKS_PER_SEC);
            if(bfile(0,tempname, PARAM_TARGET, PARAM_KEYFILE, pass_clear,
		     length, PARAM_POWER, ROUND, BLOCK_CRYPT, BLOCK_SHUFFLE, MEMORY, PARAM_VERBOSE, varinit)==0)           
              {
    printf("\n Key file does not exist or is his length is < KEYLENGTH.\n\n");
                printf("\n ERROR.\n");
	        return 0;
               }
            crypt_time = (int)(clock()/CLOCKS_PER_SEC) - crypt_time;
	
	    if (0 == strcmp(PARAM_SOURCE, PARAM_TARGET))
	     {
              if (0 != PARAM_VERBOSE)
	       printf(" Removing temp file...\n");
	      remove(tempname);
	     }
            if (0 != PARAM_VERBOSE)
             printf("\n OK, File Crypted in '%d' seconds ...\n", crypt_time);  
            return 1;
            }
           else   
            {
	    length = varinit->NB_CHAR;
            if (0 != PARAM_VERBOSE)
             printf("\n Uncrypt started, Please Wait.\n");
            crypt_time = (int)(clock()/CLOCKS_PER_SEC);
            if (bfile(1,PARAM_SOURCE, PARAM_TARGET, PARAM_KEYFILE, pass_clear,
		length, PARAM_POWER, ROUND, BLOCK_CRYPT, BLOCK_SHUFFLE, MEMORY, PARAM_VERBOSE, varinit)==0)
               {
    printf("\n Key file does not exist or is his length is < KEYLENGTH.\n\n");
                printf("\n ERROR.\n");
                return 0;
               }
            crypt_time = (int)(clock()/CLOCKS_PER_SEC) - crypt_time;
            if (0 != PARAM_VERBOSE)
             printf("\n OK, File UNcrypted in '%d' seconds ...\n", crypt_time);  
            return 1;
            }
      }
}


/*
 * Check the parameter of the program
 */
int argcheck(int argc, char **argv)
    {
	int i;
	
	for (i = 0; i < argc; i++)
	{
	
	if (strcmp(argv[i],"-c") == 0) PARAM_CRYPT=1;
 	else if (strcmp(argv[i],"-u") == 0) PARAM_UNCRYPT=1;
  	else if ((strcmp(argv[i],"-s") == 0) && (i+1 < argc))
		{
	         if (strlen(argv[i+1]) >= 200)
		    {
		     printf("\n ERROR. \nSource file name is too long. \n\n");
		     return 0;
		    }
		 strncpy(PARAM_SOURCE, argv[i+1],strlen(argv[i+1]));
		 PARAM_SOURCE[strlen(argv[i+1])]='\0';

		}
	 else if ((strcmp(argv[i],"-d") == 0) && (i+1 < argc))
		{

	         if (strlen(argv[i+1]) >= 200)
		    {
		     printf("\n ERROR. \nTARGET file name is too long. \n\n");
		     return 0;
		    }
		 strncpy(PARAM_TARGET, argv[i+1],strlen(argv[i+1]));
		 PARAM_TARGET[strlen(argv[i+1])]='\0';
		}
	 else if ((strcmp(argv[i],"-f") == 0) && (i+1 < argc)) 
		{
	         if (strlen(argv[i+1]) >= 200)
		    {
		     printf("\n ERROR. \nKEY file name is too long. \n\n");
		     return 0;
		    }
		 strncpy(PARAM_KEYFILE, argv[i+1],strlen(argv[i+1]));
		 PARAM_KEYFILE[strlen(argv[i+1])]='\0';
		}
	 else if ((strcmp(argv[i],"-k") == 0) && (i+1 < argc)) PARAM_KEYLENGTH=atoi(argv[i+1]);
	 else if ((strcmp(argv[i],"-pwd") == 0) && (i+1 < argc))
		{
		 PASSWORD = (char *) malloc(strlen(argv[i+1]) + 1);
		 strncpy(PASSWORD,argv[i+1],strlen(argv[i+1]));
		 PASSWORD[strlen(argv[i+1])]='\0';
	 	 PARAM_PASSWORD = 1;
		 } 
	 else if ((strcmp(argv[i],"-p") == 0) && (i+1 < argc)) PARAM_POWER=atoi(argv[i+1]);
	 else if ((strcmp(argv[i],"-r") == 0) && (i+1 < argc)) RANDOM=atoi(argv[i+1]);
	 else if (strcmp(argv[i],"-quiet") == 0) PARAM_VERBOSE=0;
	 else if (strcmp(argv[i],"-v") == 0) PARAM_VERBOSE=2;
	 else if (strcmp(argv[i],"-hd") == 0) MEMORY=0;
	 else if (strcmp(argv[i],"-a") == 0) PARAM_ASCII=1;
	 else if ((strcmp(argv[i],"-bc") == 0) && (i+1 < argc)) BLOCK_CRYPT=atoi(argv[i+1]);
	 else if ((strcmp(argv[i],"-bs") == 0) && (i+1 < argc)) BLOCK_SHUFFLE=atoi(argv[i+1]);
	 else if ((strcmp(argv[i],"-bk") == 0) && (i+1 < argc)) KEY_BUFFER=atoi(argv[i+1]);
	 else if ((strcmp(argv[i],"-bssl") == 0) && (i+1 < argc)) BSSL=atoi(argv[i+1]);
	 else if ((strcmp(argv[i],"-dbuf") == 0) && (i+1 < argc)) 
               {
                if ((strcmp(argv[i+1],"n") == 0)||
                    (strcmp(argv[i+1],"N") == 0)||
                    (strcmp(argv[i+1],"no") == 0)||
                    (strcmp(argv[i+1],"NO") == 0))
                     DBUFFER = 0;
               }
	 else if ((strcmp(argv[i],"-dround") == 0) && (i+1 < argc)) 
               {
                if ((strcmp(argv[i+1],"n") == 0)||
                    (strcmp(argv[i+1],"N") == 0)||
                    (strcmp(argv[i+1],"no") == 0)||
                    (strcmp(argv[i+1],"NO") == 0))
                     DROUND = 0;
               }
	 else if ((strcmp(argv[i],"-dswap") == 0) && (i+1 < argc)) 
               {
                if ((strcmp(argv[i+1],"n") == 0)||
                    (strcmp(argv[i+1],"N") == 0)||
                    (strcmp(argv[i+1],"no") == 0)||
                    (strcmp(argv[i+1],"NO") == 0))
                     DSWAP = 0;
               }
	 else if ((strcmp(argv[i],"-dshuf") == 0) && (i+1 < argc)) 
               {
                if ((strcmp(argv[i+1],"n") == 0)||
                    (strcmp(argv[i+1],"N") == 0)||
                    (strcmp(argv[i+1],"no") == 0)||
                    (strcmp(argv[i+1],"NO") == 0))
                     DSHUFFLE = 0;
               }

	 else if ((strcmp(argv[i],"-round") == 0) && (i+1 < argc)) ROUND=atoi(argv[i+1]);
	 else if (strcmp(argv[i],"-help") == 0)
	         {
		  usage();
		  options();
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
		strcpy(PARAM_ERRORFILE,"bcrypt.log");
                PARAM_ERRORFILE[strlen("bcrypt.log")]='\0';
		}
	else if (strcmp(argv[i],"-i") == 0)
		{
		INTERACTIVE = 1;
		}


       }
       
 if ((0 == INTERACTIVE) && (0 == validation())) 
        return 0;

       
return 1;
}


int validation()
{
FILE *temp_file;
if (0 == strcmp(PARAM_SOURCE,"")) 
   {
    usage();
    return 0;
   }


if (((0 == PARAM_CRYPT) && (0 == PARAM_UNCRYPT)) ||
   ((1 == PARAM_CRYPT) && (1 == PARAM_UNCRYPT)))
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


if ((0 == PARAM_UNCRYPT) && (0 == strcmp(PARAM_TARGET,"")))
   {
   strcpy(PARAM_TARGET, PARAM_SOURCE);
   }


if ((1 == PARAM_UNCRYPT) && (0 == strcmp(PARAM_TARGET,"")))
   {
    printf("\n ERROR. \n you MUST specify a target file when you uncrypt a file");
    printf("\n This file has to be different from your source file.\n\n");
    return 0;
   }


if ((1 == PARAM_UNCRYPT) && (0 == strcmp(PARAM_TARGET, PARAM_SOURCE)))
   {
    printf("\n ERROR. \n SOURCE and DEST files MUST BE different while UNcrypting.\n\n");
    return 0;
   }

if (0 != strcmp(PARAM_KEYFILE,"")) 
   {
    if ((temp_file=fopen(PARAM_KEYFILE,"rb")) == 0)
       {
	    printf("\n ERROR.");
	    printf("\n The key file '%s' does not seem to exist.\n\n",PARAM_KEYFILE);
	    return 0;
	}
    fclose(temp_file);
    }


PARAM_KEYLENGTH = (PARAM_KEYLENGTH / 8) * 8;

return 1;
}

void usage()
     {   
      printf("\n BCRYPT %s, (C) Martinez Sylvain",VERSION);
      printf("\n BUGS ALGORITHM CRYPT FILE");
      printf("\n\n Usage: bcrypt -i || [MODE] -s SOURCE_FILE {-d DEST_FILE} {-bssl nb} {OPTIONS}");
      printf("\n\n bcrypt -help : DISPLAYS HELP FOR THE OPTIONS.");
      printf("\n\n bcrypt -i    : Interactive mode where you are prompted for each parameter");
      printf("\n\n  [MODE] : ");
      printf("-c = Crypt file \n");
      printf("           -u = Uncrypt file");
      printf("\n\n Note: If you do not specify a DEST_FILE then the SOURCE_FILE is replaced by\n       the cipher result.");
      printf("\n\n {-bssl nb} : ");
      printf("Bugs Standard Security Level");
      printf("\n              This is a selection of preset security settings");
      printf("\n              Security Settings currently available:");
      printf("\n              %d:Very Low, %d:Low, %d=Medium, %d=High, %d=Very High", BSSL_VLOW, BSSL_LOW, BSSL_MEDIUM, BSSL_HIGH, BSSL_VHIGH); 
      printf("\n              Please read the HOWTO for more information\n\n");
     }

void options()
     {
      printf(" {OPTIONS}");
      printf("\n  -f key_file : Do not type a password but use a file instead");
      printf("\n  -k nb       : KEYLENGTH which has to be a 2 multiple integer.");
      printf("\n	        At least 32.");
      printf("\n	        DEFAULT = 128"); 	
      printf("\n  -p nb       : POWER used to crypt.");
      printf("\n                0 (Seed only, quick but not really strong)");
      printf("\n	        1 (Seed with random number, a bit stronger)");  
      printf("\n	        2 (Shuffle only)");  
      printf("\n	        3 (Seed and Shuffle, stronger, default)");  
      printf("\n	        4 (Seed with random number and Shuffle, strongest !)");  
      printf("\n  -r nb       : Random Number Generator.");
      printf("\n                0 (Standard C random function)");
      printf("\n	        1 (ISAAC RNG, default)");  
      printf("\n  -pwd passwd : Password you want to use to crypt/uncrypt (Not secure)");
      printf("\n  -round nb   : Nb of round of the key generator process, default=2");
      printf("\n  -bc nb      : Crypt the file using blocks of NB bytes, default = 0\n                which means all the file will be taken as only one big block.");  
      printf("\n  -bs nb      : Same as above but for the shuffle process.\n                Also, nb needs to be a multiple of %d",sizeof(TYPE_INT));  
      printf("\n  -bk nb      : Nb of the buffered keys used during the seed process\n                Default = 16.");
      printf("\n  -dbuf   y/n : Dynamic buffered keys, default = yes.");
      printf("\n  -dround y/n : Dynamic number of rounds (Key creation), default = yes.");
      printf("\n  -dswap  y/n : Dynamic modulo swap during the (Key creation), default = yes.");
      printf("\n  -dshuf  y/n : Dynamic shuffle block, default = yes.");
      printf("\n  -hd         : Crypt directly to the disk (slow but uses less memory).");        
      printf("\n  -a          : ASCII mode.\n                The crypted result will be saved in ASCII mode. Use this option\n                to decrypt a file previously crypted with this option.");        
      printf("\n  -quiet      : Does not display warnings"); 
      printf("\n  -v          : Verbose mode."); 
      printf("\n  -ef file    : Redirect errors in a file (don't specify any filename\n                if you want it to be bcrypt.log)\n\n");
     }        
