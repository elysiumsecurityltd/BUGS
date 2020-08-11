/*  
 *  bchat.c
 *
 *  Version 2.0
 *  19 November 2000 
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
 * --- V 2.0 ---
 *
 * 19/11/2000:  - You can now specify block_crypt (-bc) = 1 with
 *                power = 0 or 1
 *                This looks more like the unix talk app.
 *
 *              - Corrected minor bugs.
 *
 * --- V 1.3 ---
 *
 * 11/11/2000:  - Added BSSL options
 *
 * 08/11/2000:  - Added new library options (Dynamic options).
 *              - Change the default value of bcrypt_shuffle to sizeof(TYPE_INT)
 *              - Added the KEYFILE option !
 *
 * --- V 1.2 ---
 *
 * 03/10/2000:  - Added a '\0' after each strncpy as this is not done
 *                automatically  on all OS.
 *
 * --- V 1.1 ---
 *
 * 26/09/2000:  - Corrected a MAJOR error in the interactive mode.
 *                The new keylength, random and log values were not
 *                activated as I was not calling binit() again !
 *                Stupid thing !
 *
 *
 * --- V 1.0 --- 
 *
 * 17/09/2000:  - There is now an interactive mode letting that prompt
 *                for all the parameters
 *
 * --- V 0.7 ---
 *
 * 15/09/2000:  - Added the error output file option
 * 
 * --- V 0.6 ---
 *
 * 30/07/2000: - Added an extra parameter: -info 
 *               to display small information about the encryption process
 *
 * 
 * --- V 0.5 ---
 *
 *
 * 16/07/2000:  - New option: RNG selector
 *		- Added a parameter to binit: RANDOM
 *
 * 05/07/2000:	- Changes in the help display, added : server, serverport
 *		- Added the "-nocrypt" option
 *		- Added extra info display at startup telling the user if
 *                bchat is running as a server or client.
 *
 *
 * --- V 0.4 ---
 *
 * 22/05/2000:	- Spent all day tracing a stupid bug !!!!!
 *		  I was doing child_pid=fork();
 *		  		if (0 == fork())
 *		  instead of child_pid=fork();
 *				if (0 == child_pid)
 *		   Really stupid mistake indeed !
 *		- Tidy up the code a little bit, still quite messy but it's
 *		  only a beta version and I *haven't* got the time to write
 *		  a really good chat application !
 *
 * --- V 0.3 ---
 *
 * 20/05/2000:	- The network part seems to work fine !
 *		  Still need to improve, but it is usable and it works ! :O)
 *
 * --- V 0.2 ---
 *
 * 19/05/2000:	- Added some parameters: BUFFER, LINES, COL
 *		- It is now more a chat program than a string encryption
 *		  example ! ;o)
 *
 * --- V 0.1 ---
 *
 * 19/04/2000:  - First Implementation 
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
/*
 * Required by inet_ntoa()
 */ 
#include <netinet/in.h>
#include <arpa/inet.h>
/*
 * Required by fork()
 */
#include <unistd.h>

char *VERSION="v2.0, November 2000";


  /*
   * Default : mode = 0 (non verbose)
   *           Key's length = 128 bits
   *	       Power = 0
   *	       Key's file = 0
   */   

     int ROUND = 2;
     int BUFFER = 16;
     int BPORT_READ = 3333;
     int BPORT_SEND = 3333;
     char PARAM_SERVER[80]="no server";
     int LINES = 23;
     int COL = 80;
     int BLOCK_SHUFFLE = sizeof(TYPE_INT);
     int KEY_BUFFER = 16;
     int DROUND = 1;
     int DSWAP = 1;
     int DSHUFFLE = 1;
     int DBUFFER = 1;
     int RANDOM = 1;
     int BSSL = 0;
     int PARAM_KEYLENGTH=128;
     int PARAM_POWER=4;
     int PARAM_VERBOSE=0;   
     int PARAM_NOCRYPT=0;
     char PARAM_KEYFILE[200];
     char PARAM_ERRORFILE[200];
     int PARAM_ERROR = 0;
     int INTERACTIVE = 0;
     
     globalvar *varinit;
     int OPTION;
     char *MSG_BCHAT_STOP="EOFBCHAT_BUGS";

/*
 * These variables need to be global because I use them in my exit function
 * Yes... this is dirty ! 
 */
  int sock_read, sock_send;
  struct sockaddr_in  namer, fromr, names; /* Socket's address */

void usage(void);
int init(void);
int secure_chat(void);
int argcheck(int, char **);
int validation(void);
void bchat_end();


/*
 * Functions
 */

int main(int argc, char **argv)
{

    
  if (argcheck(argc, argv) == 0) return 0;

  if (init() == 0) return 0;

  if (secure_chat() == 0) return 0;
 
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
 * Secure chat function
 */
int secure_chat()
{
  int i,j, length=0;
  char *pass_verif, carac;
  unsigned char *pass_clear, *save_pass;
  int RETURN=10;

  int x1,x2,y1,y2;
  int bordera, borderb, infoy;

  int fromlenr = sizeof(struct sockaddr);                                   
  struct hostent *ent; 

  int child_pid;

  int prob = 0;
  int temp_power; 
    
  char *tmp_string;
  char kill_child[100];
  int tmp_buffer;

temp_power = PARAM_POWER;

pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);
pass_verif = (unsigned char *) malloc (varinit->NB_CHAR);
save_pass = (unsigned char *) malloc (varinit->NB_CHAR);

for(i=0; i < varinit->NB_CHAR; i++) pass_clear[i]='\0';

system("clear");  
printf("\n Bchat %s, (C) Martinez Sylvain",VERSION);
printf("\n BUGS ALGORITHM SECURE CHAT ");
printf("\n Libcrypt version : '%s'",varinit->LIB_VERSION);


if (1 == INTERACTIVE)
{
printf("\n\n -- INTERACTIVE MODE --"); 



j = -1;
while(j < 0)
{
printf("\n\n -> Mode [C]lient/[S]server (S)?");
carac = bcrypt_vol(1);
if( (carac == 'c') || (carac == 'C')) 
  {
   printf("\n .PLEASE NOTE THAT THE SERVER MUST BE RUNNING BEFORE THE CLIENT IS LAUNCHED");
   printf("\n -> Server address ? ");
   i=0;
   do{
             carac=bcrypt_vol(1);
             if(carac!=RETURN) 
               {
                PARAM_SERVER[i]=carac;
                printf("%c",carac);
               }
             
             i++;
      }while((i<80) && (carac!=RETURN));
    if (carac == RETURN)
       PARAM_SERVER[i - 1]='\0';

    printf("\n    .Server is %s", PARAM_SERVER);

   printf("\n -> Server Port (3333)? ");
   i=0;
   BPORT_SEND = 0;
   do{
             carac=bcrypt_vol(1);
             if(carac!=RETURN) 
               {
                BPORT_SEND = (BPORT_SEND * 10) + atoi(&carac);
                printf("%c",carac);
               }
             
             i++;
      }while((i<10) && (carac!=RETURN));

    if ( (1 == i) && (carac == RETURN)) BPORT_SEND = 3333;

    printf("\n    .Server port is %d", BPORT_SEND);
    j = 0;
  }
else 
 {  
	if( (carac == 's') || (carac == 'S')) 
	  {
	   strcpy(PARAM_SERVER,"no server");
	   printf("\n    .You are the server");
	   j = 0;
	  }
	  
	if (carac == RETURN)
	  {
	   strcpy(PARAM_SERVER,"no server");
	   printf("\n    .You are the server");
	   j = 0;
	  }
  }
}


   printf("\n -> Port where you want to receive data (3333)? ");
   i=0;
   BPORT_READ = 0;
   do{
             carac=bcrypt_vol(1);
             if(carac!=RETURN) 
               {
                BPORT_READ = (BPORT_READ * 10) + atoi(&carac);
                printf("%c",carac);
               }
             
             i++;
      }while((i<10) && (carac!=RETURN));

    if ( (1 == i) && (carac == RETURN)) BPORT_READ = 3333;
    printf("\n    .your bchat port is %d", BPORT_READ);


PARAM_NOCRYPT = -1;
while(PARAM_NOCRYPT < 0)
{
printf("\n -> Do you want to use an encrypted transmission [Y/N] (Y)?");
carac = bcrypt_vol(1);
if( (carac == 'n') || (carac == 'N')) 
  {
   PARAM_NOCRYPT = 1;
   printf("\n    .Clear text transmission selected");
  }
else
  {
    if( (carac == 'y') || (carac == 'Y')) 
      {
       PARAM_NOCRYPT = 0;
       printf("\n   .Encrypted transmission selected");
      }
      
    if (carac == RETURN)
       {
        PARAM_NOCRYPT = 0;
        printf("\n   .Encrypted transmission selected");
       }
   }
}



if (0 == PARAM_NOCRYPT)
   {
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

}



PARAM_VERBOSE = -1;
while((PARAM_VERBOSE < 0) || (PARAM_VERBOSE > 2))
{
printf("\n -> Verbose Level [0/1/2] (0)?");
carac = bcrypt_vol(1);

PARAM_VERBOSE=atoi(&carac);

if (carac == RETURN)
  {
   PARAM_VERBOSE = 0;
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

   printf("\n   .Nb of Round is %d", ROUND);


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

BUFFER = -1;
while(BUFFER < 0)
{
printf("\n -> Datagram Buffer (16)? ");

   i=0;
   BUFFER = 0;
   do{
             carac=bcrypt_vol(1);
             if(carac!=RETURN) 
               {
                BUFFER = (BUFFER * 10) + atoi(&carac);
                printf("%c",carac);
               }
             
             i++;
      }while((i<10) && (carac!=RETURN));

    if ( (1 == i) && (carac == RETURN)) BUFFER = 16;

}

    printf("\n   .Datagram Buffer is %d", BUFFER);


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

LINES = -1;
while(LINES < 0)
{
printf("\n -> Number of Lines of your terminal (23)? ");


   i=0;
   LINES = 0;
   do{
             carac=bcrypt_vol(1);
             if(carac!=RETURN) 
               {
                LINES = (LINES * 10) + atoi(&carac);
                printf("%c",carac);
               }
             
             i++;
      }while((i<10) && (carac!=RETURN));

    if ( (1 == i) && (carac == RETURN)) LINES = 23;
}

    printf("\n   .Terminal Lines number is %d", LINES);


COL = -1;
while(COL < 0)
{
printf("\n -> Number of Columns of your terminal (80)? ");


   i=0;
   COL = 0;
   do{
             carac=bcrypt_vol(1);
             if(carac!=RETURN) 
               {
                COL = (COL * 10) + atoi(&carac);
                printf("%c",carac);
               }
             
             i++;
      }while((i<10) && (carac!=RETURN));

    if ( (1 == i) && (carac == RETURN)) COL = 80;
}

    printf("\n   .Terminal Columns number is %d", COL);


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
else
 printf("\n KEY'S LENGTH used : %d.",PARAM_KEYLENGTH);


if (0 == validation())
    {
     printf("\n Error while trying to validate the parameters\n\n");
     return 0;
    }

if (1 == INTERACTIVE)
	binit(PARAM_KEYLENGTH, RANDOM, PARAM_ERRORFILE, PARAM_ERROR, varinit);

varinit->MISC = 0;

if (0 == BSSL)
 {


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
  temp_power=bssl(BSSL, &ROUND, &BUFFER, &BLOCK_SHUFFLE, varinit,PARAM_VERBOSE);
  if (0 < temp_power)
   PARAM_POWER = temp_power;

  BUFFER = varinit->NB_CHAR;
 }

PARAM_KEYLENGTH = varinit->KEYLENGTH;

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
       printf("\n Power            : (1) Random Seed.");
   if (2 == PARAM_POWER)
       printf("\n Power            : (2) Shuffle only.");
   if (3 == PARAM_POWER)
       printf("\n Power            : (3) Seed and Shuffle.");
   if (4 == PARAM_POWER)
       printf("\n Power            : (4) Random Seed and Shuffle.");

   if (0 == RANDOM)
      printf("\n RNG               : (0) Standard C Algorithm.");
   if (1 == RANDOM)
       printf("\n RNG              : (1) ISAAC Algorithm.");

    if (0 != strcmp(PARAM_KEYFILE, ""))
	{
	 printf("\n Key File          : '%s'.",PARAM_KEYFILE);
	}

printf("\n\n For help use: bchat -help \n\n");
printf("\n\n Chat in progress... \n\n");

if (0 == strcmp(PARAM_SERVER,"no server"))
   printf("\n\n *** YOU ARE THE SERVER *** \n\n");
else
   printf("\n\n *** You are the client *** \n\n"); 

if (1 == PARAM_NOCRYPT)
{
  printf("\n ATTENTION ! Network transmission won't be encrypted, do you want to continue ? (y/n) \n");

 if (bcrypt_vol(1) != 'y') return 0;
}
else
{

    if (0 == strcmp(PARAM_KEYFILE,""))
     {  
          i=0;
          printf(" SESSION Password -> ");
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

         if(length >= (varinit->NB_CHAR /2))
           {
        
               printf("\n Re-type Password -> ");
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

              if(strcmp((char *) pass_clear,pass_verif)==0)
                 {
                  printf("\n Secure Chat started, Please Wait.\n");
                 }
	      else 
	         {
		  printf("\n You misspelled it. Bchat session finished.\n");
	          return 0;
	         }

	}
	else
	 {
	  printf("\n The minimum password length is %d \n",(varinit->NB_CHAR / 2));
          return 0;
	 } 
    }
   else
     length = varinit->NB_CHAR;

}	 
bordera = (LINES / 2);
borderb = bordera + 2;
infoy = bordera + 1;
x1 = 1;
x2 = 1;
y1 = 1;
y2 = borderb + 1;

if ((1 == PARAM_POWER) || (4 == PARAM_POWER)) prob = 1;


tmp_buffer = BUFFER+(prob * varinit->NB_CHAR);
if (tmp_buffer < strlen(MSG_BCHAT_STOP))
 tmp_buffer = strlen(MSG_BCHAT_STOP);

tmp_string = (char *) malloc(tmp_buffer);

printf("\n HOY ! tmp_buffer = %d \n",tmp_buffer);

system("clear");
gotoxy(0,bordera,LINES,COL);
for (i=0; i<COL; i++) printf("-");
gotoxy(0,borderb,LINES,COL);
for (i=0; i<COL; i++) printf("-");
gotoxy(0,0,LINES,COL);

gotoxy(1,infoy,LINES,COL);
for (j=0; j<COL; j++) printf(" ");
gotoxy(1,infoy,LINES,COL);
printf("Creating Connection on port #%d...",BPORT_READ);
fflush(stdout);


/*
 * Socket read creation
 */

   sock_read = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_read < 0) {
        perror("Error while opening datagram socket (read)");
        exit(1);
    }
 
    /* Address initialisation */
    namer.sin_family = AF_INET;
    namer.sin_addr.s_addr = INADDR_ANY;
    namer.sin_port =htons(BPORT_READ);

i = 0;
while(i < 100)
     { 
    /* Attach socket to the address */
    if (bind(sock_read, (struct sockaddr *)&namer, sizeof(namer)))
       {
        i++;
	BPORT_READ++;
        namer.sin_port =htons(BPORT_READ);
	if (100 == i)
	   {
	        printf("\nError.\n bind socket datagram. Range %d -> %d already in use \n",(BPORT_READ - 100), BPORT_READ);
	        exit(1);
	   }
       }
        else i=100;
     }

/*
 * Socket send creation
 */

sock_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_send < 0) {
        perror("Error while creating the datagram socket (send)");
        exit(1);
    }

gotoxy(1,infoy,LINES,COL);
for (j=0; j<COL; j++) printf(" ");
gotoxy(1,infoy,LINES,COL);
printf("Waiting Connection on port #%d...",BPORT_READ);
fflush(stdout);

if (0 != strcmp(PARAM_SERVER,"no server"))
   {

   ent = gethostbyname(PARAM_SERVER);

    if (ent == 0) {
        fprintf(stderr, "%s:  Unknown host \n", PARAM_SERVER);
        exit(2);
       }
    bcopy(ent->h_addr, &names.sin_addr, ent->h_length);
    names.sin_family = AF_INET;
    names.sin_port = htons(BPORT_SEND);

sprintf(tmp_string,"%d",BPORT_READ);

    if (sendto(sock_send, tmp_string, strlen(tmp_string), 0,
        (struct sockaddr *)&names, sizeof(names)) < 0)
        perror("Error sending datagram message");

gotoxy(1,infoy,LINES,COL);
for (j=0; j<COL; j++) printf(" ");
gotoxy(1,infoy,LINES,COL);
printf("Connected. Local Port: %d / Remote IP: %s, Remote Port: %d",BPORT_READ, ent->h_name, BPORT_SEND);


   }
else
  {
  if (recvfrom(sock_read, tmp_string, tmp_buffer,0,(struct sockaddr *) &fromr,&fromlenr) < 0)
        perror("receiving datagram packet");


BPORT_SEND = atoi(tmp_string);

    ent = gethostbyaddr((char *) &fromr.sin_addr.s_addr , sizeof(fromr.sin_addr.s_addr), AF_INET);

    bcopy(ent->h_addr, &names.sin_addr, ent->h_length);

    names.sin_family = AF_INET;
    names.sin_port = htons(BPORT_SEND);


gotoxy(1,infoy,LINES,COL);
for (j=0; j<COL; j++) printf(" ");
gotoxy(1,infoy,LINES,COL);
printf("Connected. Local Port: %d / Remote IP: %s, Remote Port: %d",BPORT_READ, ent->h_name, BPORT_SEND);

  }


signal(SIGINT,bchat_end);


/*
 * Child processus creation
 */
child_pid = fork();

if (0 == child_pid)
{

i=0;
tmp_string[i]=' ';
fflush(stdout);

/*
 * SENDING DATAGRAM 
 */
while(1==1)
      {
	i=0;
	while(i<BUFFER)
	{
	 tmp_string[i]=bcrypt_vol(1);

	 if (tmp_string[i] == '\n')
	 	{
  /*
   * We do that to erase the rest of the previous content of the tmp_string;
   */
		 for (j=i+1; j < tmp_buffer; j++) tmp_string[j] = ' ';
		 i = BUFFER;
	 	 x1 = 1;
	 	 y1++;
	 	 if (y1 <= (bordera - 1)) 
	 	    {
	 	      gotoxy(x1,y1,LINES,COL);
	 	      for (j=0; j<COL; j++) printf(" ");
		      gotoxy(x1,y1,LINES,COL);
	 	    }
	 	}

	 if (y1 > (bordera - 1))
	    {
	     x1 = 1;
	     y1 = 1;
	     gotoxy(x1,y1,LINES,COL);
	     for (j=0; j<COL; j++) printf(" ");
	    }

         gotoxy(x1,y1,LINES,COL);

	 if (i < BUFFER)
	    {
	     printf("%c",tmp_string[i]);
	     x1++;
	     if (x1 >= COL)
	     {
	      x1 = 1;
	      y1++;
 	      if (y1 <= (bordera - 1)) 
	 	    {
	 	      gotoxy(x1,y1,LINES,COL);
	 	      for (j=0; j<COL; j++) printf(" ");
	 	      gotoxy(x1,y1,LINES,COL);
	 	    }

	    }
     /*  i++; */
	   }
       i++;
       }

for (i=0; i<length; i++)
 save_pass[i] = pass_clear[i];


if (0 == PARAM_NOCRYPT)
{
                 if(bstream(0,(unsigned char *)tmp_string, BUFFER, PARAM_KEYFILE, save_pass, length,
                    PARAM_POWER, ROUND, BLOCK_SHUFFLE, PARAM_VERBOSE, varinit) == 0)
                   {
                   printf("\n ERROR.\n");
                   bchat_end();
                   return 0;
                   }

}

    if (sendto(sock_send, tmp_string, tmp_buffer, 0, (struct sockaddr *)&names, sizeof(names)) < 0)
	{
	gotoxy(1,infoy,LINES,COL);
	for (j=0; j<COL; j++) printf(" ");
	gotoxy(1,infoy,LINES,COL);
	printf("CANNOT REACH REMOTE CLIENT. Disconnecting ...");
	fflush(stdout);
	close(sock_send);
	close(sock_read);
	bcrypt_vol(0);
	exit(1);
	}

   }
}


i=0;
tmp_string[i]=' ';

/*
 * RECEIVING DATAGRAM
 */
while (1==1)
  {
  fflush(stdout);

    if (recvfrom(sock_read, tmp_string, tmp_buffer,0,(struct sockaddr *) &fromr,&fromlenr) < 0)
        perror("receiving datagram packet");

/*  if (recvfrom(sock_read, tmp_string, (BUFFER+(prob * varinit->NB_CHAR)),0,(struct sockaddr *) &fromr,&fromlenr) < 0)
        perror("receiving datagram packet");
*/

if (0 == strncmp(tmp_string,MSG_BCHAT_STOP,strlen(MSG_BCHAT_STOP)))
   {
	gotoxy(1,infoy,LINES,COL);
	for (j=0; j<COL; j++) printf(" ");
	gotoxy(1,infoy,LINES,COL);
	printf("REMOTE CLIENT STOPPED TRANSMISSION. Disconnecting ...");
	fflush(stdout);
	sprintf(kill_child,"kill -9 %d",child_pid);
	system(kill_child);
	close(sock_send);
	close(sock_read);
	bcrypt_vol(0);
	exit(1);
   }

for (i=0; i<length; i++) save_pass[i] = pass_clear[i];

if (0 == PARAM_NOCRYPT)
{

           if (bstream(1,(unsigned char *)tmp_string, (BUFFER+(prob * varinit->NB_CHAR)), PARAM_KEYFILE, save_pass, length,
                PARAM_POWER, ROUND, BLOCK_SHUFFLE, PARAM_VERBOSE, varinit)==0)
               {
                printf("\n ERROR.\n");
                return 0;
               }
}


i=0;
  while(i<BUFFER)
      {
     if (tmp_string[i] == '\n')
        {
	 i = BUFFER;
         x2 = 1;
         y2++;
         if (y2 < LINES)
            {
              gotoxy(x2,y2,LINES,COL);
              for (j=0; j<COL; j++) printf(" ");
            }
 
        }
     if (y2 >= LINES)
        {
         x2 = 1;
         y2 = borderb + 1;
         gotoxy(x2,y2,LINES,COL);
         for (j=0; j<COL; j++) printf(" ");
        }

     gotoxy(x2,y2,LINES,COL);

     if (i < BUFFER) 
	{
	 printf("%c",tmp_string[i]);
     	 x2++;

         if (x2 >= COL)
         {
          x2 = 1;
          y2++;
          if (y2 < LINES)
            {
              gotoxy(x2,y2,LINES,COL);
              for (j=0; j<COL; j++) printf(" ");
              gotoxy(x2,y2,LINES,COL);
            }
	  } 
        }
     i++; 
    }                                            

  }              
}

                        
void bchat_end()
{
/*
 * We need to do this to reconfigure the terminal
 * As the break signal must have been sent while the application 
 * was waiting for a keystroke (bcrypt_vol(1))
 */
bcrypt_vol(0);

sendto(sock_send, MSG_BCHAT_STOP, strlen(MSG_BCHAT_STOP), 0,(struct sockaddr *)&names, sizeof(names));

close(sock_send);
close(sock_read);

exit(0);
}

/*
 * Check the parameter of the program
 */
int argcheck(int argc, char **argv)
    {
	int i;

	for (i = 0; i < argc; i++)
	{
	 if (strcmp(argv[i],"-help") == 0)
	    {
	      usage();
	      return 0;
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
	 else if ((strcmp(argv[i],"-p") == 0) && (i+1 < argc)) PARAM_POWER=atoi(argv[i+1]);
	 else if ((strcmp(argv[i],"-r") == 0) && (i+1 < argc)) RANDOM=atoi(argv[i+1]);
	 else if (strcmp(argv[i],"-v") == 0) PARAM_VERBOSE=2;
	 else if (strcmp(argv[i],"-info") == 0) PARAM_VERBOSE=1;
	 else if (strcmp(argv[i],"-quiet") == 0) PARAM_VERBOSE=0;
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
	 else if ((strcmp(argv[i],"-buffer") == 0) && (i+1 <argc)) BUFFER=atoi(argv[i+1]);
	 else if ((strcmp(argv[i],"-lines") == 0) && (i+1 <argc)) LINES=atoi(argv[i+1]);
	 else if ((strcmp(argv[i],"-col") == 0) && (i+1 <argc)) COL=atoi(argv[i+1]);
	 else if ((strcmp(argv[i],"-server") == 0) && (i+1 <argc)) strncpy(PARAM_SERVER,argv[i+1],strlen(argv[i+1])%80);
	 else if ((strcmp(argv[i],"-serverport") == 0) && (i+1 <argc)) BPORT_SEND=atoi(argv[i+1]);
	 else if ((strcmp(argv[i],"-port") == 0) && (i+1 <argc)) BPORT_READ=atoi(argv[i+1]);
	 else if (strcmp(argv[i],"-nocrypt") ==0) PARAM_NOCRYPT=1;
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
		strcpy(PARAM_ERRORFILE,"bchat.log");
                PARAM_ERRORFILE[strlen("bchat.log")]='\0';
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

if (PARAM_KEYLENGTH < 32) 
    {
     printf("\n ERROR.");
     printf("\nKEYLENGTH MUST BE > 32.\n\n");
     return 0;    
    }

if ((PARAM_POWER > 4) || (PARAM_POWER < 0))
    {
     printf("\n ERROR.");
     printf("\n POWER MUST BE 0 or 1.\n\n");
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
      printf("\n BCHAT %s, (C) Martinez Sylvain",VERSION);
      printf("\n BUGS ALGORITHM SECURE CHAT");
      printf("\n\n Usage: bchat -i || [MODE] {-bssl nb} {OPTIONS}");
      printf("\n\n bchat -i    : Interactive mode where you are prompted for each parameter");
      printf("\n\n {-bssl nb} : ");
      printf("Bugs Standard Security Level");
      printf("\n              This is a selection of preset security settings");
      printf("\n              Security Settings currently available:");
      printf("\n              %d:Very Low, %d:Low, %d=Medium, %d=High, %d=Very High", BSSL_VLOW, BSSL_LOW, BSSL_MEDIUM, BSSL_HIGH, BSSL_VHIGH); 
      printf("\n              Please read the HOWTO for more information\n\n");
      printf("\n\n {OPTIONS}");
      printf("\n  -help       : Display this help.");
      printf("\n  -server nb  : Nb is the IP address of the bchat server you try to connect to");
      printf("\n  -serverport nb : Nb is the server port number you want to connect to");
      printf("\n  -port nb    : Nb is your own port you want to run bchat on");
      printf("\n  -f key_file : Do not type a password but use a file instead");
      printf("\n  -k nb       : KEYLENGTH which has to be a 2 multiple integer.");
      printf("\n	        At least 32.");
      printf("\n	        DEFAULT = 128"); 	
      printf("\n  -p nb       : POWER used to crypt.");
      printf("\n                0 (Seed only, quick but not really strong)");
      printf("\n	        1 (Seed with random number, a bit stronger)");  
      printf("\n	        2 (Shuffle only)");  
      printf("\n	        3 (Seed and Shuffle, stronger)");  
      printf("\n	        4 (Seed with random number and Shuffle, strongest, )");  
      printf("\n  -r nb       : Random function used.");
      printf("\n                0 (Standard C random function)");
      printf("\n	        1 (ISAAC RNG, default)");  
      printf("\n  -round nb   : ROUND of the key generator process, default=2");
      printf("\n  -bs nb      : Size of the shuffle blocks used in the crypt process.\n	        Also, nb needs to be a multiple of %d",sizeof(TYPE_INT));  
      printf("\n  -bk nb      : Nb of the buffered keys used during the seed process\n                Default = 16.");
      printf("\n  -dbuf   y/n : Dynamic buffered keys, default = yes.");
      printf("\n  -dround y/n : Dynamic number of rounds (Key creation), default = yes.");
      printf("\n  -dswap  y/n : Dynamic modulo swap during the (Key creation), default = yes.");
      printf("\n  -dshuf  y/n : Dynamic shuffle block, default = yes.");
      printf("\n  -buffer nb  : Size of the text buffer that will be crypted in BYTES (default = 16)");
      printf("\n  -nocrypt    : If you don't want to crypt the network transmission");
      printf("\n  -lines nb   : Number of lines of your terminal (Default = 23)");
      printf("\n  -col nb     : Number of columns of your terminal (Default = 80");
      printf("\n  -quiet      : Does not display any warning. (Default)"); 
      printf("\n  -v          : Verbose mode.");
      printf("\n  -info       : Display few extra information.");
      printf("\n  -ef file    : Redirect errors in a file (don't specify any filename\n                if you want it to be bchat.log)\n\n");
     }        
