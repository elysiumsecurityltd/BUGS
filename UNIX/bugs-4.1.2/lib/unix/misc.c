/*
 * misc.c
 *
 * MISCALLENAENOUS FUNCTIONS
 *
 *  B U G S - LIBRARY
 *
 *  DYNAMIC CRYPTOGRAPHY ALGORITHM
 *  Version 4.1.0 - "IBIZA"
 *  26 July 2002 
 *
 *  -> generate passwd
 *  -> crypt file
 *  -> crypt stream
 *  -> make secure multi-users programms
 *
 *   Created by MARTINEZ Sylvain
 *
 *   Based on the BUGS crypt's algorithm of MARTINEZ Sylvain
 *   (Big and Usefull Great Security)
 *
 *  Copyright 1996-2002 MARTINEZ Sylvain
 *  THIS IS FREE SOFTWARE; YOU CAN REDISTRIBUTE IT AND/OR MODIFY IT UNDER
 *  THE TERMS OF THE GNU GENERAL PUBLIC LICENSE, see the file COPYING.
 */

/*
 * This is my own header
 */
#define _BUGSCRYPT_MISC

#include "../../include/misc.h"
#include "../../include/main.h"  
#include "../../include/utils.h"  
#include "../../include/fpos_t.h"

/*
 * === TEST PASSWD FUNCTION ===
 *
 * test if the passwd is right
 */
int
bcrypt_test_passwd
 (int round, TYPE_INT *code_file, unsigned char *pass_clear, int length,
  int mode, globalvar *varinit)
{

 TYPE_INT *pass_code;

/*
 * On linux OS, rand() return an unsigned int
 */
 unsigned int random_key;

/*
 * pass_code will receive the numerical value of the characters
 * swap_length will receive the different lengths of the different swaps
 */
 pass_code = (TYPE_INT *) malloc (varinit->NB_CHAR);

 if (bcrypt_test_length (pass_clear, length, mode, varinit) == 0)
  return 0;

 if (bcrypt_transcription (pass_clear, pass_code, mode, varinit) == 0)
  return 0;

 if (bcrypt_add (pass_code, mode, varinit) == 0)
  return 0;

 if (bcrypt_swap (pass_code, round, mode, varinit) == 0)
  return 0;

 random_key = bcrypt_read_key (pass_code, code_file, mode, varinit);

 if (bcrypt_code (1, random_key, pass_code, mode, varinit) == 0)
  return 0;

 return bcrypt_comparison(code_file, pass_code, mode, varinit);
}


/*
 * === READ PASSWD FUNCTION ===
 *
 * find the old passwd to allow the algorithm to compare it later
 */
int
bcrypt_read_passwd
 (char *user, char *file_path, TYPE_INT *code_file, int mode,
  globalvar *varinit)
{

 int i;
 FILE *file_name;

 typedef struct
  {
   char *name;
   TYPE_INT *pass;
  }
 enreg;

 enreg *var;

 var = (enreg *) malloc (varinit->USER_LENGTH + varinit->NB_CHAR);
 var->name = (char *) malloc(varinit->USER_LENGTH);
 var->pass = (TYPE_INT *) malloc(varinit->NB_CHAR);

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Read passwd function started.");
   fflush(BCRYPTLOG);
  }
 file_name = fopen (file_path, "rb");
 if (file_name == NULL)
  return 0;

 fseek (file_name, 0, 0);

 do
  {
   do
	{
     fread (var->name, varinit->USER_LENGTH, 1, file_name);
     fread (var->pass, varinit->NB_CHAR, 1, file_name);
	}
   while ((feof (file_name) == 0) &&
         (strncmp (user, var->name, strlen (user)) != 0));
  }
/*
 * That avoid the confusion between two login like :
 *  bugs and bugsophile
 * If we did not do the following comparison, these 2 logins
 * would have been equal.
 */
 while ((feof (file_name) == 0) && (strlen (var->name) != strlen (user)));


 if ((strncmp (user, var->name, strlen (user)) != 0) || 
	(strlen (var->name) != strlen (user)))
  {
   fclose (file_name);
   return 0;
  }

 fclose(file_name);

 if ((1 == mode) || (2 == mode))
  {
   fprintf(BCRYPTLOG, "\n User '%s' found in the file '%s'.", user, file_path);
   fflush(BCRYPTLOG);
  }

/*
 * We take the user passwd
 */
 for (i = 0; i < (varinit->NB_CHAR / varinit->NB_BYTE); i++)
  code_file[i] = var->pass[i];

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n -> Read passwd funtion Finished.");
   fflush(BCRYPTLOG);
  }

 return 1;

}


/*
 * === READ KEY FUNCTION ===
 *
 * Use to find the random number used when the algorithm first
 * crypted the passwd.   
 */
TYPE_INT
bcrypt_read_key
 (TYPE_INT *pass_code, TYPE_INT *code_file, int mode, globalvar *varinit)
{
 TYPE_INT random_key, j;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Read key function Started.");
   fflush(BCRYPTLOG);
  }
   
 j = pass_code[0] % varinit->NB_INDEX;
 random_key = code_file[j] ^ pass_code[j];

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n -> Read key function Finished.");
   fflush(BCRYPTLOG);
  }

 return random_key;

}


/*
 * === COMPARISON FUNCTION ===
 *
 * Compare the passwd give by the user with the passwd archived
 */
int
bcrypt_comparison
 (TYPE_INT *code_file, TYPE_INT *pass_code, int mode, globalvar *varinit)
 {

int i = 0;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Comparison funtion Started.");
   fflush(BCRYPTLOG);
  }

 while ( (i < varinit->NB_INDEX) && (code_file[i] == pass_code[i]) )
  {
   i++;
  }

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n -> Comparison funtion Finished.");
   fflush(BCRYPTLOG);
  } 

 if (i == varinit->NB_INDEX) return 1;

 if ((1 == mode) || (2 == mode))
  {
   fprintf(BCRYPTLOG, "\n ERROR.\nComparison function failed.");
   fflush(BCRYPTLOG);
  }

 return 0;

}

/*  
 * === WRITE PASSWD FUNCTION ===
 *
 * Write the cipher text in a file (such as /etc/passwd)
 *
 */
int 
bcrypt_write_passwd
 (char *user, TYPE_INT *pass_code, char *file_path, int mode,
  globalvar *varinit)
{
 FILE *file_name;
 fpos_t pos;
 int i;

 typedef struct
  {
   char *name;
   TYPE_INT *pass;
  }
 enreg;

 enreg *var;

 var = (enreg *) malloc (varinit->USER_LENGTH + varinit->NB_CHAR);
 var->name = (char *) malloc(varinit->USER_LENGTH);
 var->pass = (TYPE_INT *) malloc (varinit->NB_CHAR);

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Write passwd function started.");
   fprintf(BCRYPTLOG,"\n    Passwd archive file name : %s.",file_path);
   fflush(BCRYPTLOG);
  }
 
 file_name = fopen (file_path, "r+b");

 if (file_name != NULL)
  {
   fseek (file_name, 0, 0);
   do
	{
     do
      {
       fgetpos (file_name, &pos);
       fread (var->name, varinit->USER_LENGTH, 1, file_name);
       fread (var->pass, varinit->NB_CHAR, 1, file_name);
      }
     while ((feof (file_name) == 0) &&
           (strncmp (var->name, user, strlen (user)) != 0));
	}
   while ((feof (file_name) == 0) &&
         (strlen (var->name) != strlen (user)));

   if (strncmp (var->name, user, strlen (user)) == 0)
	fsetpos (file_name, &pos);
  }
 else
  {
   file_name = fopen (file_path, "wb");
  }

 strncpy (var->name, user, varinit->USER_LENGTH);
 for (i = 0; i < varinit->NB_INDEX; i++)
 var->pass[i] = pass_code[i];

 fwrite (var->name, varinit->USER_LENGTH, 1, file_name);
 fwrite (var->pass, varinit->NB_CHAR, 1, file_name);

 fclose (file_name);

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n -> Write passwd file function finished.");
   fflush(BCRYPTLOG);
  }

 return 1;

}

/*
 * === WRITE KEY FUNCTION ===
 *
 * Write the key in a file (such as /etc/key)
 *
 */
int 
bcrypt_write_keyfile
 (unsigned char *pass_clear, char *file_path, int mode, globalvar *varinit)
{

 FILE *file_name;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Write key function started.");
   fprintf(BCRYPTLOG,"\n    Key archive file name : %s.",file_path);
   fflush(BCRYPTLOG);
  }

 file_name = fopen (file_path, "wb");

 fwrite (pass_clear, varinit->NB_CHAR, 1, file_name);

 fclose (file_name);

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n -> Write key file function finished.");
   fflush(BCRYPTLOG);
  }
 if (BCRYPTLOG != stderr) fclose(BCRYPTLOG);

 return 1;

}

/*
 * === READ KEY FUNCTION ===
 * Read the key from  file (such /etc/key)
 */
int
bcrypt_read_keyfile
 (unsigned char *pass_clear, char *file_path, int mode, globalvar *varinit)
{

 FILE *file_name;
 int file_length;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Read key function started.");
   fprintf(BCRYPTLOG,"\n    Key archive file name : %s.",file_path);
   fflush(BCRYPTLOG);
  }

 file_name = fopen (file_path, "rb");

 fseek(file_name,0,2);
 file_length = ftell(file_name);
 if (file_length < varinit->NB_CHAR)
  {
   fclose(file_name);
   return 0;
  }

/*
 * If the file's length is > to the keylength
 * then I will take the data in the middle of the file.
 * It is more secure, in case of the file has always the same header
 * and footer.
 * If the file's length is <= to the keylength
 * That is not worth it, and the key file SHOULD have been generated
 * with bcrypt_key_generator !
 */
 if (file_length > (varinit->NB_CHAR * 2))
  fseek(file_name,(file_length / 2),0);
 else
  fseek(file_name,0,0);

 fread (pass_clear, varinit->NB_CHAR, 1, file_name);
 fclose (file_name);

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n -> Read key file function finished.");
   fflush(BCRYPTLOG);
  }

 return 1;

}

/*
 * === WRITE HIDE FUNCTION ===
 *
 * Put some data in afile
 * choice = 0 -> at the begining of the file
 * choice = 1 -> at the end of the file
 *
 */
RETURN_TYPE
bcrypt_write_hide
 (int choice, char *source_file, char *dest_file, globalvar *varinit, int mode)
{

 FILE *file_s, *file_d, *file_old;
 TYPE_INT file_s_length, file_d_length;
 int i;
 char *carac, *name;

 carac = (char *) malloc(1);

 if ((1 == mode) || (2 == mode))
  {
   fprintf(BCRYPTLOG, "\n\n -> Write hide function started.");
   fprintf(BCRYPTLOG,"\n    Source file name : %s.",source_file);
   fprintf(BCRYPTLOG,"\n    Destination file name : %s.",dest_file);
   if (choice == 0)
    fprintf(BCRYPTLOG, "\n    Write data at the : BEGINING");
   else
    fprintf(BCRYPTLOG, "\n    Write data at the : END");
   fflush(BCRYPTLOG);
   }

/*
 * I do a +4 because I'm gonna add the extension to the filename (.old)
 * and I also add +2 because I am gonna the \0 to the filename.
 * So it's a total of +6
 * I know that \0 is only one character. But I just prefer do a +2
 * just in case it's not always like that on all OS (call me paranoid ;o)
 */
 name = (char *) malloc(strlen(dest_file) + 6);
 i = 0;
 do
  {
   name[i] = dest_file[i];
   i++;
  }
 while( (i<strlen(dest_file)) && (dest_file[i] != '.') );

 name[i]='\0';

 strcat(name,".old");

 if ((1 == mode) || (2 == mode))
  {
   fprintf(BCRYPTLOG, "\n    Backup destination file in '%s'.",name);
   fflush(BCRYPTLOG);
  }
   
  file_s = fopen (source_file, "rb");
  file_d = fopen (dest_file, "r+b");
  file_old = fopen (name, "w+b");

/*
 * Check if the source file exists
 */
 if (NULL == file_s)
  {
   if ((1 == mode) || (2 == mode))
    fprintf(BCRYPTLOG,"\n ERROR.\nSource file does not seem to exist.");

   fflush(BCRYPTLOG);

   fclose(file_d);
   fclose(file_old);

   if (BCRYPTLOG != stderr) fclose(BCRYPTLOG);
   return 0;
  }

/*
 * Check if the Destination file has been opened OK
 */
 if (NULL == file_d)
  {
   if ((1 == mode) || (2 == mode))
    fprintf(BCRYPTLOG,"\n ERROR.\nCannot open Destination file.");

   fflush(BCRYPTLOG);

   fclose(file_s);
   fclose(file_old);

   if (BCRYPTLOG != stderr) fclose(BCRYPTLOG);
   return 0;
  }

/*
 * Check if the Backup file has been created OK
 */
 if (NULL == file_old)
  {
   if ((1 == mode) || (2 == mode))
    fprintf(BCRYPTLOG,"\n ERROR.\nCannot Create Backup file.");

   fflush(BCRYPTLOG);

   fclose(file_s);
   fclose(file_d);

   if (BCRYPTLOG != stderr) fclose(BCRYPTLOG);
   return 0;
  }

 fseek(file_d,0,2);
 fseek(file_s,0,2);

 file_d_length = ftell(file_d);
 file_s_length = ftell(file_s);

 fseek(file_d,0,0);
 fseek(file_s,0,0);
 fseek(file_old,0,0);

 if ((1 == mode) || (2 == mode))
  {
   fprintf(BCRYPTLOG,"\n    Backup destination file in progress.");
   fflush(BCRYPTLOG);
  }

 for (i = 0; i < file_d_length; i++)
  {
   fread(carac, 1, 1, file_d);
   fwrite(carac, 1, 1, file_old);
  }

 if ((1 == mode) || (2 == mode))
  {
   fprintf(BCRYPTLOG,"\n    Backup finished.");
   fflush(BCRYPTLOG);
  }
 fseek(file_d,0,0);
 fseek(file_old,0,0);

 if (choice == 0)
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG,"\n    Writing data at the begining of the file.");
     fflush(BCRYPTLOG);
    }

   bcrypt_fwrite_int (&file_s_length, sizeof(TYPE_INT), 1,
                      file_old,varinit,mode);

   for (i = 0; i < file_s_length; i++)
    {
     fread(carac, 1, 1, file_s);
     fwrite(carac, 1, 1, file_d);
    }
  }

 if ((1 == mode) || (2 == mode))
  {
   fprintf(BCRYPTLOG, "\n    Writing destination data.");
   fflush(BCRYPTLOG);
  }

 for (i = 0; i < file_d_length; i++)
  {
   fread(carac,1,1,file_old);
   fwrite(carac,1,1,file_d);
  }

 if (choice == 1)
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG,"\n    Writing data at the end of the file");
     fflush(BCRYPTLOG);
    }

   for (i = 0; i < file_s_length; i++)
    {
     fread(carac,1,1,file_s);
     fwrite(carac,1,1,file_d);
    }

   bcrypt_fwrite_int(&file_s_length, sizeof(TYPE_INT), 1,
                     file_d,varinit,mode);
  }

 fclose(file_s);
 fclose(file_d);
 fclose(file_old);

 if ((1 == mode) || (2 == mode))
  {
   fprintf(BCRYPTLOG, "\n -> Write hide function finished.");
   fflush(BCRYPTLOG);
  }

 if (BCRYPTLOG != stderr) fclose(BCRYPTLOG);

 return 1;

}


/*
 * === READ HIDE FUNCTION ===
 *
 * Put some data in afile
 * choice = 0 -> at the begining of the file
 * choice = 1 -> at the end of the file
 *
 */
RETURN_TYPE 
bcrypt_read_hide
(int choice, char *source_file, char *dest_file, globalvar *varinit, int mode)
{

 FILE *file_s, *file_d;
 TYPE_INT file_s_length, file_d_length;
 int i;
 char *carac;
  
 carac = (char *) malloc(1);

 if ((1 == mode) || (2 == mode))
  {
   fprintf(BCRYPTLOG, "\n\n -> Read hide function started.");
   fprintf(BCRYPTLOG,"\n    Source file name : %s.",source_file);
   fprintf(BCRYPTLOG,"\n    Destination file name : %s.",dest_file);
   if (choice == 0)
    fprintf(BCRYPTLOG, "\n    Read data from the : BEGINING");
   else
    fprintf(BCRYPTLOG, "\n    Read data from the : END");
   fflush(BCRYPTLOG);
  }

 file_s = fopen (source_file, "rb");
 file_d = fopen (dest_file, "rb");

 if (file_d != NULL)
  {
   if ((1 == mode) || (2 == mode))
    fprintf(BCRYPTLOG,"\n ERROR.\nCannot open Destination file.");

   if (BCRYPTLOG != stderr) fclose(BCRYPTLOG);
   return 0;
  }

 file_d = fopen(dest_file, "wb");

 if (file_s == NULL || file_d == NULL)
  {
   fclose(file_s);
   fclose(file_d);

   if ((1 == mode) || (2 == mode))
    fprintf(BCRYPTLOG,"\n ERROR.\nCannot open Source file.");

   if (BCRYPTLOG != stderr) fclose(BCRYPTLOG);
    return 0;
  }

 fseek(file_s,0,2);
 file_s_length = ftell(file_s);

 fseek(file_d,0,0);
 fseek(file_s,0,0);

 if (choice == 0)
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG,
             "\n    Extracting hide data from the begining of the file.");
     fflush(BCRYPTLOG);
    }

   bcrypt_fread_int(&file_d_length, sizeof(TYPE_INT), 1, file_s,varinit,mode);

   if (file_d_length > file_s_length)
    {
     if ((1 == mode) || (2 == mode))
      fprintf(BCRYPTLOG,
              "\n ERROR.\nThe data extracted are bigger than the source file.");

      if (BCRYPTLOG != stderr) fclose(BCRYPTLOG);
       return 0;
    }

   for (i = 0; i < file_d_length; i++)
    {
     fread(carac, 1, 1, file_s);
     fwrite(carac, 1, 1, file_d);
    }
  }
 else
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG,"\n    Extracting Hide data from the end of the file");
     fflush(BCRYPTLOG);
    }

   fseek(file_s, -(sizeof(TYPE_INT)), 2);

   bcrypt_fread_int(&file_d_length, sizeof(TYPE_INT), 1,
                    file_s,varinit, mode);

   if (file_d_length > file_s_length)
    {
     if ((1 == mode) || (2 == mode))
      fprintf(BCRYPTLOG,
              "\n ERROR.\nThe data extracted are bigger than the source file.");

     if (BCRYPTLOG != stderr) fclose(BCRYPTLOG);
      return 0;
    }

   fseek(file_s, -(file_d_length + sizeof(TYPE_INT)), 2);

   for (i = 0; i < file_d_length; i++)
    {
     fread(carac,1,1,file_s);
     fwrite(carac,1,1,file_d);
    }
  }

 fclose(file_s);
 fclose(file_d);

 if ((1 == mode) || (2 == mode))
  {
   fprintf(BCRYPTLOG, "\n -> Hide function finished.");
   fflush(BCRYPTLOG);
  }

 if (BCRYPTLOG != stderr) fclose(BCRYPTLOG);

 return 1;

}

/*
 * === DELETE PASSWD FUNCTION ===
 * 
 * Delete a user from a password file
 *
 */
int
bcrypt_delete_passwd
 (char *pass_file, char *user, int keylength, int mode, globalvar *varinit)
{

 FILE *file_s, *file_old;
 fpos_t pos, pos_old;
 char *carac;

 typedef struct
  {
   char *name;
   TYPE_INT *pass;
  }
 enreg;

 enreg *var;

 var = (enreg *) malloc (varinit->USER_LENGTH + varinit->NB_CHAR);
 var->name = (char *) malloc(varinit->USER_LENGTH);
 var->pass = (TYPE_INT *) malloc (varinit->NB_CHAR);

 carac = (char *) malloc(1);

 if ((1 == mode) || (2 == mode))
  {
   fprintf(BCRYPTLOG, "\n\n -> Delete passwd function started.");
   fprintf(BCRYPTLOG,"\n    Passwd file name : %s.",pass_file);
   fprintf(BCRYPTLOG,"\n    User name : %s.",user);
   fprintf(BCRYPTLOG,"\n    KEYLENGTH : %d",keylength);
   fprintf(BCRYPTLOG,"\n    Old passwd file : pass.old");
   fflush(BCRYPTLOG);
  }

 file_s = fopen (pass_file, "rb");

 if (file_s == NULL)
  {
   fclose(file_s);
   if (BCRYPTLOG != stderr) fclose(BCRYPTLOG);
   return 0;
  }

 if ((1 == mode) || (2 == mode))
  {
   fprintf(BCRYPTLOG, "\n    Locating user.");
   fflush(BCRYPTLOG);
  }

 do
  {
   do
    {
     fgetpos (file_s, &pos);
     fread (var->name, varinit->USER_LENGTH, 1, file_s);
     fread (var->pass, varinit->NB_CHAR, 1, file_s);
    }
   while ((feof (file_s) == 0) &&
         (strncmp (user, var->name, strlen (user)) != 0));
  }
/*
 * That avoid the confusion between two login like :
 *  bugs and bugsophile
 * If we did not do the following comparison, these 2 logins
 * would have been equal.
 */
 while ((feof (file_s) == 0) && (strlen (var->name) != strlen (user)));

 if ((feof (file_s) != 0) &&
    (strncmp (user, var->name, strlen (user)) != 0))
  {
   fclose (file_s);
   return 0;
  }

 if ((1 == mode) || (2 == mode))
  {
   fprintf(BCRYPTLOG,
           "\n    User '%s' found in the file '%s'.", user, pass_file);
   fflush(BCRYPTLOG);
  }

/*
 * We delete the user passwd
 */
 file_old = fopen ("pass.old", "wb");
 fseek (file_s, 0, 0);
 fseek (file_old, 0, 0);

 if ((1 == mode) || (2 == mode))
  {
   fprintf(BCRYPTLOG,"\n    Saving password file in 'pass.old'.");
   fflush(BCRYPTLOG);
  }
    
 fread(carac, 1, 1, file_s);

 do
  {
   fwrite(carac, 1, 1, file_old);
   fread(carac, 1, 1, file_s);
  }
 while(feof(file_s) == 0);

/*
 * I have to close the file if I want to put the EOF flag
 */
 fclose(file_old);
 fclose(file_s);
 if(remove(pass_file) != 0)
  {
   return 0;
  }
 file_s = fopen(pass_file,"wb");
 file_old = fopen("pass.old","rb");

 if (file_s == NULL || file_old == NULL)
  return 0;

 fseek (file_old, 0, 0);

 fgetpos(file_old, &pos_old);

#if _NEWFPOS_T == 1
 while (pos_old.__pos < pos.__pos)
  {
   fread (var->name, varinit->USER_LENGTH, 1, file_old);
   fread (var->pass, varinit->NB_CHAR, 1, file_old);
   fwrite(var->name, varinit->USER_LENGTH, 1, file_s);
   fwrite(var->pass, varinit->NB_CHAR, 1, file_s);
   fgetpos (file_old, &pos_old);
  }
#else
 while (pos_old < pos)
  {
   fread (var->name, varinit->USER_LENGTH, 1, file_old);
   fread (var->pass, varinit->NB_CHAR, 1, file_old);
   fwrite(var->name, varinit->USER_LENGTH, 1, file_s);
   fwrite(var->pass, varinit->NB_CHAR, 1, file_s);
   fgetpos (file_old, &pos_old);
  }
#endif

#if _NEWFPOS_T == 1
 pos_old.__pos = pos_old.__pos + varinit->USER_LENGTH + varinit->NB_CHAR;
#else
 pos_old = pos_old + varinit->USER_LENGTH + varinit->NB_CHAR;
#endif

 fsetpos(file_old, &pos_old);

 fread (var->name, varinit->USER_LENGTH, 1, file_old);
 fread (var->pass, varinit->NB_CHAR, 1, file_old);

 while(feof(file_old) == 0)
  {
   fwrite(var->name, varinit->USER_LENGTH, 1, file_s);
   fwrite(var->pass, varinit->NB_CHAR, 1, file_s);
   fread (var->name, varinit->USER_LENGTH, 1, file_old);
   fread (var->pass, varinit->NB_CHAR, 1, file_old);
  }

 fclose(file_s);
 fclose(file_old);

 if ((1 == mode) || (2 == mode))
  {
   fprintf(BCRYPTLOG, "\n -> Delete passwd funtion Finished.");
   fflush(BCRYPTLOG);
  }

 return 1;

}

