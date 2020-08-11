/*  
 *  blogin.c
 *
 *  Version 3.1
 *  12 September 2003 
 *
 *   LOGIN PROGRAM
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

/* PLEASE READ THE FOLLOWING :


                              USAGE  WARNING
                              --------------

 YOU MUST CREATE A PASSWORD FILE WITH THE PROGRAM : 'bpass'
 this is an example that use a password file called 'codes'.

 if you want to use this program instead of your login shell :
   
     YOU MUST EXECUTE go_shell TO COMPILE THIS PROGRAM !!!!!!

 if you do not do that, you may not be able to log in your account 
 anymore ...

     This version shows how to administrate several users when you 
     are just a user without root privilege:
     You have to compile this programm, and then you have to 
     make a passwd file with "bpass", after, you have to do 
                    chsh ~/bugs-4.1.1/blogin username
     and then, when you enter your login and your passwd, a second 
     menu appear, the menu of blogin... 
     IMPORTANT: THe file codes MUST be in your root path (ex: ~/codes)
    
     Then, even if you give your first passwd to someone he won't be 
     able to come in your account.

     Caracteristics : 
	
             - FTP isn't available => more secure
             - Passwd file isn't readable by anybody except root 
             - You can allow only One or two commands to someone 
               (mail, news, etc)
     There's only ONE problem, if your provider use the Pop mail server    
     then If someone have the first passwd, he could read your mail.

     Also, make sure your home dir is chmod 700 and that blogin is in the 
     allowed shells (/etc/shells)
*/

/*
 * This program has been only tested on a LINUX and HPUX OS
 * And I will not be responsible for anything if you use this program
 * It works for me and I find it very usefull, but is dangerous to use ...
 */

/*
 * HISTORY
 *
 * --- V 3.1 ---
 *
 * 12/09/2003:  - Updated the blogin help with the default -u USER settings
 *
 * --- V 3.0 ---
 *
 * 22/11/2002:  - Change the default mode from 1 to 0 (Quiet) 
 *		- Change default path for the password file to $HOME/bpasswd
 *		- You can now define the path and filename of the password file
 *		- Changed the menu. You can now select to SU as a user.
 *
 * --- V 2.4 ---
 *
 * 03/10/2000:  - Added a '\0' after each strncpy as this is not done automatically
 *                on all OS.
 *
 *
 * --- V 2.3 ---
 *
 * 15/09/2000:  - Added the error output file option
 *
 * --- V 2.2 ---
 *
 *
 * 16/07/2000:  - Added a parameter to binit: RANDOM
 *		  which is set to any value you want, as it won't be used
 *		  in this appliciation
 *
 * 05/07/2000:  - Minor problem in the way I was allocating memory for
 *                the variables receiving the FILE NAMES.
 *                This could cause problem when using filename < 3
 *
 * --- V 2.1 ---
 *
 * 19/05/2000 : - Added the 2 new parameters required by gotoxy, line and col
 *
 *
 * --- V 2.0 ---
 *
 * 24/04/2000 :	- First implementation with the new library
 *
 * --- V 1.9 ---
 *
 * 26/07/1999 : - Replaced sizeof() by strlen() while calling malloc()
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
 * 11/01/1998 : - Added global variable VERSION
 *              - Started to do an HISTORY
 */

/*
 * This header is important
 * There is some global variables that you will need, eg:
 * USER_LENGTH = size of the string that contain the user name
 * other reserved variable name : KEYLENGTH, NB_CHAR, varinit->NB_INDEX, etc
 * Read the documentation or have a look of this header for more information
 */       
#include "../include/wrapper.h"
#include "../include/utils.h" 
#include "../include/misc.h" 
#include "../include/extra.h"
#include <unistd.h>

char *VERSION="v3.1, September 2003";

/*
 * Default : mode = 0 (non verbose)
 *           Key's length = 128 bits
 */  
int MODE = 0;
int ROUND = 2;
int PARAM_KEY = 128;
char PARAM_USER[200];
char PARAM_ERRORFILE[200];
int PARAM_ERROR = 0;
globalvar *varinit;

int LINES = 24;
int COL = 80;

/*
 * Password file
 */
char PARAM_PWD[200];

/*
 * Functions
 */

void usage(void);
int init(void);
int argcheck(int, char **);
int login(char **);

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
   if (login(argv) == 0) return 0;

return 1;
}

/*
 * Login function
 */
int login(char **argv)
{
  int test, i, length, nb_char = 20, RETURN = 10;
  char carac, *user, *cmd;
  unsigned char *pass_clear;
  TYPE_INT *code_file;
  
cmd = (char *) malloc(100);
user = (char *) malloc(20);
pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);
code_file = (TYPE_INT *) malloc (varinit->NB_CHAR);

if (strlen(PARAM_USER) > varinit->USER_LENGTH)
   {
    printf("\n User name length too big. Max = '%d'.\n ERROR. \n",varinit->USER_LENGTH);
    return 0;
   }

  printf ("\n Login for %s\n", PARAM_USER);

  test = 0;

  if (bcrypt_read_passwd (PARAM_USER, PARAM_PWD, code_file, MODE, varinit) != 0)
    {
      do{
      if (0 == MODE) system("clear");
      printf("\n BLOGIN %s, (C) Martinez Sylvain",VERSION);
      printf("\n Login demonstration program.");
      printf("\n Libcrypt version '%s'",varinit->LIB_VERSION);
      printf("\n For help please use: blogin -help");
      if (0 == MODE) gotoxy(20,10,LINES,COL);
      else printf("\n");
      printf(" Welcome in BUGSLAND \n\n");
      if (0 == MODE) gotoxy(10,14,LINES,COL);
      printf(" 1) su \n");
      if (0 == MODE) gotoxy(10,16,LINES,COL);
      printf(" 0) Exit \n");
/*      if (0 == MODE) gotoxy(10,18,LINES,COL);
      printf(" RETURN) Shell \n");
      */
      carac = bcrypt_vol(1);
     /*
      * If you want your family to access only to their mail
      * then define a pine config where they can only access to one
      * mail folder
      * I use that with my family ...
      * after, I send mails on my account with a keyword, and this these mails
      * are automaticly saved in my family folder.
      */
      if (carac == '1' )
	 {
	 printf ("\nUser -> ");
         i = 0;
          do
            {
             carac = bcrypt_vol (1);
             if (carac != RETURN) 
		{
	         user[i] = carac;
		 printf("*");
		}
             i++;
            }
          while (i < nb_char && (carac != RETURN));
	  printf("\n");

          if (carac == RETURN) user[i - 1] = '\0';

	  strcpy(cmd,"su - ");
	  strcat(cmd, user);
          system(cmd);
	  exit(1);
	 }
      if (carac == '0' ) exit(1); 
      }while (carac != RETURN);

      printf ("\nPassword -> ");
      i = 0;
      do
	{
	  carac = bcrypt_vol (1);
	  if (carac != RETURN) pass_clear[i] = carac;
	  i++;
	}
      while (i < varinit->NB_CHAR && (carac != RETURN));
      if (carac == RETURN)
        {
        pass_clear[i - 1] = '\0';
        length = i - 1;
        }
       else
         length = i;

      test = blogin (code_file, pass_clear, length, 0, ROUND, MODE, varinit);

    }
  else
    printf ("\n USER %s NOT REGISTRED ", PARAM_USER);
  if (test == 0)
    {
      printf ("\n ACCESS DENIED \n");
      return 0;
    }
  else
    {
      printf ("\n ACCESS ALLOWED \n");
      system("sh");
      return 1;
    }
}


/*
 * Initialised the global variables
 */
int init()
{
varinit = (globalvar *) malloc(sizeof(globalvar));
/*
 * The log will be generated in the stderr output
 * The RANDOM paramter is set to 1, but it won't be used in this 
 * application.
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
	if ((0 == strcmp(argv[i],"-u")) && (i+1 < argc))
	   {
                 if (strlen(argv[i+1]) >= 200)
                    {
                     usage();
                     printf("\n ERROR. \nUSER name is too long. \n\n");
                     return 0;
                    }
		strcpy(PARAM_USER, argv[i+1]);
                PARAM_USER[strlen(argv[i+1])]='\0';
	   }

	if ((0 == strcmp(argv[i],"-k")) && (i+1 < argc))
	   {
		PARAM_KEY = atoi(argv[i+1]);
	   }
	if ((0 == strcmp(argv[i],"-round")) && (i+1 < argc))
	   {
		ROUND = atoi(argv[i+1]);
	   }

	if (0 == strcmp(argv[i],"-v")) MODE = 2;

	if (0 == strcmp(argv[i],"-quiet")) MODE = 0;
	else if ((strcmp(argv[i],"-ef") == 0) && (i+1 < argc))
		{

	         if (strlen(argv[i+1]) >= 200)
		    {
                     usage();
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
		strcpy(PARAM_ERRORFILE,"blogin.log");
                PARAM_ERRORFILE[strlen("blogin.log")]='\0';
		}

	if ((strcmp(argv[i],"-pf") == 0) && (i+1 < argc))
	   {
            if (strlen(argv[i+1]) >= 200)
               {
		usage();
                printf("\n ERROR. \nERROR Password file name is too long. \n\n");
                return 0;
               }
            strncpy(PARAM_PWD, argv[i+1],strlen(argv[i+1]));
            PARAM_PWD[strlen(argv[i+1])]='\0';
           }
		
	if (0 == strcmp(argv[i],"-help"))
	   {
            usage();
	    return 0;
	   }
      }
   if (0 == strcmp(PARAM_PWD,""))
      {
       strcpy(PARAM_PWD,getenv("HOME"));
       strcat(PARAM_PWD,"/bpasswd");
      }

   if (0 == strcmp(PARAM_USER,""))
      {
	strcpy(PARAM_USER,getenv("LOGNAME"));
      }
   if (fopen(PARAM_PWD,"r") == 0)
       {
	usage();
        printf("\n ERROR.");
        printf("\n password file '%s' not found. \n\n",PARAM_PWD);
        return 0;
        }
return 1;
}
   
void usage()
{
  printf("\n BLOGIN %s, (C) Martinez Sylvain",VERSION);
  printf("\n\n USAGE : blogin {OPTIONS}");
  printf("\n\n {OPTIONS} :");
  printf("\n  -u USER  : Default is your login name defined by $LOGNAME.");
  printf("\n  -k nb    : KEYLENGTH which has to be a 2 multiple integer.");
  printf("\n             At least 32.");
  printf("\n             DEFAULT = 128");
  printf("\n\n  -round nb: Complexity of the key generator process, default=2");
  printf("\n  -quiet   : Does not display any warning.\n\n");
  printf("\n  -v : Verbose mode.");
  printf("\n  -ef file : Redirect errors in a file (don't specify any filename\n                if you want it to be blogin.log)\n");
  printf("\n  -pf file  : password file (default: ~/bpasswd)\n");
  printf("\n  -help    : Displays application options\n\n");
}
