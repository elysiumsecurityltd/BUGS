/*  
 *  bmore.c
 *
 *  Version 1.0
 *  11 November 2000 
 *
 *   SECURE MORE
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
 * 11/11/2000:  - Added the PARAM_KEY parameter to bstream()
 *                However I am not using it in this application
 *                this is just to be able to use the new library
 *
 * --- V 0.3 ---
 *
 * 03/10/2000:  - Added a '\0' after each strncpy as this is not done
 *                automatically on all OS.
 *
 * --- V 0.2 ---
 *
 * 15/09/2000:  - Added the error output file option
 *
 * --- V 0.1 ---
 *
 * 30/07/2000:  - Everything seems to work fine. 
 *
 * 28/07/2000:	- Started application 
 *
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

     int ROUND = 2;
     char PARAM_SOURCE[200]="";
     int LINES = 23;
     int COL = 80;
     int BLOCK_SHUFFLE = 0;
     int RANDOM = 1;
     int PARAM_KEYLENGTH=128;
     int PARAM_POWER=4;
     int PARAM_VERBOSE=1;   
     char PARAM_ERRORFILE[200];
     int PARAM_ERROR = 0;
     globalvar *varinit;

void usage(void);
int init(void);
int secure_more(void);
int argcheck(int, char **);
void bchat_end();
/*
 * Functions
 */

int main(int argc, char **argv)
{

    
  if (argcheck(argc, argv) == 0) return 0;

  if (init() == 0) return 0;

  if (secure_more() == 0) return 0;
 
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
int secure_more()
{
  int i,j,k,tmp,length,buffer;
  char carac;
  unsigned char *pass_clear;
  int RETURN=10;
  FILE *FILE_SOURCE;

  unsigned char *tmp_string;

pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);

for(i=0; i < varinit->NB_CHAR; i++) pass_clear[i]='\0';

system("clear");  
printf("\n Bmore %s, (C) Martinez Sylvain",VERSION);
printf("\n BUGS ALGORITHM SECURE MORE ");
printf("\n Libcrypt version : '%s'",varinit->LIB_VERSION);
printf("\n\n KEY'S LENGTH used : %d.",PARAM_KEYLENGTH);
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

       printf("\n\n TERMINAL LINES   : %d",LINES);
	   printf("\n TERMINAL COL     : %d",COL);
printf("\n\n For help use: bmore -help \n\n");
printf("\n\n Secure more in progress... \n\n");

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

         if(length >= (varinit->NB_CHAR /2))
                  printf("\n Secure more started, Please Wait.\n");
	else
	 {
	  printf("\n The minimum password length is %d \n",(varinit->NB_CHAR / 2));
          return 0;
	 } 

FILE_SOURCE = fopen(PARAM_SOURCE,"rb");

if (NULL == FILE_SOURCE)
   {
    printf("\nCANNOT OPEN THE SOURCE FILE : '%s'\n",PARAM_SOURCE);
    return 0;
  }
fseek(FILE_SOURCE,0,2);
buffer = ftell(FILE_SOURCE);
fseek(FILE_SOURCE,0,0);

tmp = buffer / 4;
if ((tmp * 4) < buffer)
   {
    tmp = ((tmp * 4) + 4);
   }
else
  tmp = tmp*4;
    
tmp_string = (unsigned char *) malloc(tmp);
fread(tmp_string,1,buffer,FILE_SOURCE);

           if (bstream(1,tmp_string, buffer, "", pass_clear, length,
                PARAM_POWER, ROUND, BLOCK_SHUFFLE, PARAM_VERBOSE, varinit)==0)
               {
                printf("\n ERROR.\n");
                return 0;
               }

		   tmp_string[buffer - (varinit->NB_CHAR)] = '\0';

		   j = 0;
		   k = 0;

		    printf("<PRESS ANY KEY TO CONTINUE>\n");  
			
           for (i = 0; i<buffer - (varinit->NB_CHAR); i++)
               {
			    if ((j < COL) && (tmp_string[i] != 10))
				   {
					printf("%c",tmp_string[i]);
					j++;
				   }
				else
				   {
					j = 0;
					k++;
					printf("\n");
				   }
				if (LINES == k)
				   {
				    printf("<PRESS ANY KEY TO CONTINUE>");
				    bcrypt_vol(1);
					printf("\n");
					k = 0;
				   }
			 }

		   for (i=0;i<buffer;i++) tmp_string[i]=' ';
		   free(tmp_string);
					
return 1;
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
	 if (strcmp(argv[1],"-help") == 0)
	    {
	      usage();
	      return 0;
	    }
         else
           {
		   for (i=1; i<argc; i++)
	        {
		    if ((strcmp(argv[i],"-lines") == 0) && (i+1 <argc))
			{
					i++;
					LINES=atoi(argv[i]);
			}
		    else if ((strcmp(argv[i],"-col") == 0) && (i+1 <argc))
			{
				    i++;
				    COL=atoi(argv[i]);
			}
		    else if (strcmp(argv[i],"-quiet") == 0) PARAM_VERBOSE=0;
		    else if (strcmp(argv[i],"-v") == 0) PARAM_VERBOSE=2;   
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
			strcpy(PARAM_ERRORFILE,"bmore.log");
                        PARAM_ERRORFILE[strlen("bmore.log")]='\0';
			}

                    else
                      {
                       strncpy(PARAM_SOURCE,argv[1],strlen(argv[1])%199);
                       PARAM_SOURCE[(strlen(argv[i])%199)]='\0';
		      }
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
      printf("\n BMORE %s, (C) Martinez Sylvain",VERSION);
      printf("\n BUGS ALGORITHM SECURE MORE REPLACEMENT");
      printf("\n\n Usage: bchat [MODE] {OPTIONS}");
      printf("\n\n {OPTIONS}");
      printf("\n  -help       : Display this help.");
      printf("\n  -lines nb   : Number of lines of your terminal (Default = 23)");
      printf("\n  -col nb     : Number of columns of your terminal (Default = 80");
      printf("\n  -quiet      : Does not display any warning. (Default)"); 
      printf("\n  -v          : Verbose mode.");
      printf("\n  -ef file    : Redirect errors in a file (don't specify any filename\n                if you want it to be bmore.log)\n\n");
     }        
