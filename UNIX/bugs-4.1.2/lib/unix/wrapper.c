/*
 * wrapper.c
 *
 * WRAPPER FUNCTIONS
 *
 *  B U G S - LIBRARY
 *
 *  DYNAMIC CRYPTOGRAPHY ALGORITHM
 *  Version 4.1.0 - "ARMISTICE"
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
#define _LIBCRYPT_WRAPPER

#include "../../include/wrapper.h"
#include "../../include/main.h" 
#include "../../include/utils.h" 
#include "../../include/misc.h" 
#include "../../include/shuffle.h" 
#include "../../include/seed.h"

/*
 * === INIT FUNCTION ===
 *
 * The global variables will be initiallized
 * ATTENTION THIS IS DIFFERENT FROM THE MODE in the other fonctions.
 * mode = 0  : stderr log output
 * mode = 1  : file log output
 * mode = 2  : internal binit call, no redefinition on the error output
 */
RETURN_TYPE 
binit
 (int length, int random, char *file_name, int mode, globalvar *varinit)
{
 int i, read_ret = 0;
 FILE *rand_file;

/*
 * this value will show the progress of the crypt/decrypt process in %
 */
 if (2 != mode)
  varinit->PROGRESS = 0;

 if (0 == mode)
  {
   BCRYPTLOG = stderr;
   fprintf(BCRYPTLOG, "\n -> INITIALISATION in progress... ");
   fflush(BCRYPTLOG);
  }

 if (1 == mode)
  {
   if (NULL == file_name)
    file_name = "bugslib.log";

   if (NULL == (BCRYPTLOG = fopen(file_name,"a+b")))
    return 0;
          
   fprintf(BCRYPTLOG, "\n -> INITIALISATION in progress... ");
   fflush(BCRYPTLOG);
  }

/*
 * NB_BYTE's value is the number of bit of the integer that I use
 * in this algorithm and defined by TYPE_INT
 */
 varinit->NB_BYTE = sizeof(TYPE_INT);

 varinit->NB_BITS = varinit->NB_BYTE * 8;

 varinit->NB_SHIFT = 0;
 i = varinit->NB_BITS;
 while (i >= 2)
  {
   varinit->NB_SHIFT++;;
   i = i / 2;
  }

 if ((0 == mode) || (1 == mode))
  {
   fprintf(BCRYPTLOG, "\n Standard type has bytes/bits = %d/%d.",
           varinit->NB_BYTE, varinit->NB_BITS );
   fflush(BCRYPTLOG);
  }

/* How many bits in your key ?
 * default is 128 bits = 16 characters
 * minimum is 64 = 8 characters
 * Always use number that are a multiple of 2 !!
 * and ALWAYS >= 64 ! if you want something usefull
 * and ALWAYS >= 32 ! if you want that's work
 */ 

 if (length < varinit->NB_BITS)
  {
   if (1 >= mode)
    {
     fprintf(BCRYPTLOG, "\n ERROR.\nKEYLENGTH should be at least %d \n",
            varinit->NB_BITS);
     fflush(BCRYPTLOG);
     if (BCRYPTLOG != stderr)
      fclose(BCRYPTLOG);
     return 0;
    }
  }

 varinit->KEYLENGTH = length;
 varinit->NB_CHAR = (varinit->KEYLENGTH / 8); 
 varinit->NB_INDEX = (varinit->NB_CHAR / varinit->NB_BYTE);

 varinit->USER_LENGTH = 20;

/*
 * Default RANDOM Number Generator to use
 * if you want a differnet one you need to overwrite this value after
 * calling binit()
 * Default = 1 = ISAAC RNG
 */
 varinit->RANDOM = random;

 if (varinit->NB_BYTE < 4)
  {
   if (varinit->RANDOM != 0)
   if ((0 == mode) || (1 == mode))
    {
     fprintf(BCRYPTLOG, "\n FORCED TO Standard C RNG as default \n");
     fflush(BCRYPTLOG);
     varinit->RANDOM = 0;
    }
  }
        
/*
 * Initial SEED for the RNG
 * If you haven't /dev/random, this is a REALLY basic initialisation please 
 * overwrite this value after you called binit() by a better seed specific
 * of your operating system.
 *
 * This initialisation is based on the work of John Viega (viega@list.org)
 *
 * rewrote by Simon Huot <sh_ct@hotmail.com>:
 * I think its cleaner that way,  also it did not close the file :)
 *
 */
 rand_file  = fopen("/dev/urandom", "r");
 if (NULL == rand_file)
  rand_file  = fopen("/dev/random", "r");
 
 if (NULL == rand_file)
  {
   varinit->SEED = (TYPE_INT)time(NULL) + clock();
   if(mode<= 1) fprintf(BCRYPTLOG,
                        "\n Random initialisation: BASIC (time and clock)");      
   fflush(BCRYPTLOG);
  }
 else
  {
   if(mode<= 1) fprintf(BCRYPTLOG,
                        "\n Random initialisation: DEVICES (/dev/urandom)");
   fflush(BCRYPTLOG);
  
   while(!read_ret)
    read_ret = fread(&varinit->SEED, sizeof(unsigned int), 1, rand_file);
   fclose(rand_file);
  }

/*
 * The library will only stop if this variable is set to 1
 */
 i = 1;
 if (*(char *)&i == 1)
  varinit->BCRYPT_ENDIAN = 0;
 else
  varinit->BCRYPT_ENDIAN = 1;

 if ((0 == mode) || (1 == mode))
  {
   if (1 == varinit->BCRYPT_ENDIAN)
    fprintf(BCRYPTLOG, "\n System using BIG Endian.");
   else
    fprintf(BCRYPTLOG, "\n System using LITTLE Endian. (default)");

   fflush(BCRYPTLOG);
  }

 if (2 != mode)
  {
   varinit->KEY_BUFFER = 16;

   if ((0 == mode) || (1 == mode))
    {
     fprintf(BCRYPTLOG, "\n Default Key BUFFER = %d.",varinit->KEY_BUFFER);
     fflush(BCRYPTLOG);
    }

   varinit->MISC = BMASK_ROUND | BMASK_SWAP | BMASK_SHUFFLE | BMASK_BUFFER; 
  }

 strncpy(varinit->LIB_VERSION,"4.0.0",10);

 if (1 >= mode) 
  {
   fprintf(BCRYPTLOG, "\n -> INITIALISATION FINISHED \n");
   fflush(BCRYPTLOG);
  }

 if (varinit->PROGRESS >= 100)
  varinit->PROGRESS = 100;
 else
  varinit->PROGRESS = varinit->PROGRESS + 10;

 return 1;

}

/*
 * === KEY GENERATOR function ===
 * 
 * Generate long key in a file
 * Minimum key length : 128
 *
 */
RETURN_TYPE
bkey_generator
 (unsigned char *pass_param, int length, int round, char *file_path,
  int power, int random, int mode, globalvar *varinit)
{
 int i, j, k, l, shift = 0, shiftfix;
 TYPE_INT *pass_code;
 globalvar *varsaved;
 unsigned char *pass_clear;

 if (1 <= mode)
  {
   fprintf(BCRYPTLOG, "\n -> Key generator function started.");
   fflush(BCRYPTLOG);
  }

 if (varinit->KEYLENGTH < 128)
  {
   if (1 <= mode)
    {
     fprintf(BCRYPTLOG, "\n ERROR.\nYou can only generate key >= 128 bits.");
     fflush(BCRYPTLOG);
    }
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);
   return 0;
  }

 if ((varinit->KEYLENGTH / varinit->NB_BITS) < 2)
  {
   if (1 <= mode)
    {
     fprintf(BCRYPTLOG, "\n ERROR.\nThe KEYLENGTH needs to be at least twice");
     fprintf(BCRYPTLOG, "\nthe size of your integer type, in your case >= %d.",
            (varinit->NB_BITS * 2));
     fflush(BCRYPTLOG);
    }
   if (BCRYPTLOG != stderr) fclose(BCRYPTLOG);
   return 0;
  }

/*
 * pass_code will receive the numerical value of the characters
 */
 pass_code = (TYPE_INT *) malloc (varinit->NB_CHAR);
 pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);

 if (NULL == pass_clear)
  { 
   if(mode>= 1)
    {
     fprintf(BCRYPTLOG,"\n ERROR.\nOUT OF MEMORY! (bkey_generator)");
     fflush(BCRYPTLOG);
    }
   return 0;                               
  }
 
 if (power == 0)
  {
   if (1 <= mode)
    {
     fprintf(BCRYPTLOG, "\n    Key length that will be generated : %d.",
             varinit->KEYLENGTH);
     fflush(BCRYPTLOG);
    }

   varsaved = (globalvar *) malloc(sizeof(globalvar));

   if (random == 0)
    {
     memcpy(pass_clear, pass_param, length);
     bclean_string(pass_param, length, mode);
	 if (1 <= mode)
      {
       fprintf(BCRYPTLOG,"\n    Random Initialisation already done.\n");
       fflush(BCRYPTLOG); 
      }
    }

   binit(128, varinit->RANDOM, "", 2, varsaved);

   if (random == 1)
    {
     if (1 <= mode)
      {
       fprintf(BCRYPTLOG,"\n    Random initialisation in progress.");
       fflush(BCRYPTLOG);
      }

     for (i = 0; i < varsaved->NB_CHAR; i++)
     pass_clear[i] = (char) brand(varinit, mode);
 
     length = varsaved->NB_CHAR;
    }

   i = 128;

   if (varinit->PROGRESS >= 100)
    varinit->PROGRESS = 100;
   else
    varinit->PROGRESS += 10;

   do
    {
     if (1 <= mode)
      {
       fprintf(BCRYPTLOG,"\n    Current length key = %d.",i);
       fflush(BCRYPTLOG);
      }
  
     if (bcrypt_test_length (pass_clear, length, mode, varsaved) == 0)
      {
       if (1 <= mode)
        {
         fprintf(BCRYPTLOG, "\n ERROR.\nCouldn't generated key.");
         fflush(BCRYPTLOG);
        }

       bclean_string(pass_clear, length, mode);
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);
       return 0;
      }

     if (bcrypt_transcription (pass_clear, pass_code, mode, varsaved) == 0)
      {
       if (1 <= mode)
        {
         fprintf(BCRYPTLOG, "\n ERROR.\nCouldn't generated key.");
         fflush(BCRYPTLOG);
        }

       bclean_string(pass_clear, length, mode);
       bclean_typeint(pass_code, varsaved->NB_INDEX,mode);
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);
       return 0;
      }

     if (bcrypt_add (pass_code, mode, varsaved) == 0)
      {
       if (1 <= mode)
        {
         fprintf(BCRYPTLOG, "\n ERROR.\nCouldn't generated key.");
         fflush(BCRYPTLOG);
        }

       bclean_string(pass_clear, length, mode);
       bclean_typeint(pass_code, varsaved->NB_INDEX,mode);
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);
       return 0;
      }

     if (bcrypt_swap (pass_code, round, mode, varsaved) == 0)
      {
       if (1 <= mode)
        {
         fprintf(BCRYPTLOG, "\n ERROR.\nCouldn't generated key.");
         fflush(BCRYPTLOG);
        }

       bclean_string(pass_clear, length, mode);
       bclean_typeint(pass_code, varsaved->NB_INDEX,mode);
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);
       return 0;
      }

     if (bcrypt_code (0, 0, pass_code, mode, varsaved) == 0)
      {
       if (1 <= mode)
        {
         fprintf(BCRYPTLOG, "\n ERROR.\nCouldn't generated key.");
         fflush(BCRYPTLOG);
        }
  
       bclean_string(pass_clear, length, mode);
       bclean_typeint(pass_code, varsaved->NB_INDEX,mode);
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);
       return 0;
      }
/*
 * We translate the long integer from pass_code into some characters
 * in the string pass_clear
 */
     l=0;
     k=0;
     j=0;

     shiftfix=varinit->NB_BITS - 8;

     do
      {
       if (0 == l)
        shift = shiftfix;
       else
        shift = shift - 8;
  
       pass_clear[j] = (int)((pass_code[k] << shift) >> shiftfix);
  
       l++;
       if (l == varsaved->NB_BYTE)
        {
         l = 0;
         k++;
        }
       j++;

      }
     while (k < varsaved->NB_INDEX);

     i = i * 2;
     length = varsaved->NB_CHAR;
     binit(i, varinit->RANDOM, "", 2, varsaved);

     if (varinit->PROGRESS >= 100)
      varinit->PROGRESS = 100;
     else
      varinit->PROGRESS = varinit->PROGRESS + 10;
 
    }
   while (i <= varinit->KEYLENGTH);

   if (bcrypt_write_keyfile (pass_clear, file_path, mode, varinit) == 0)
    {
     if (1 <= mode)
      {
       fprintf(BCRYPTLOG, "\n ERROR.\nCouldn't WRITE key.");
       fflush(BCRYPTLOG);
      }

     bclean_string(pass_clear, length, mode);
     if (BCRYPTLOG != stderr)
      fclose(BCRYPTLOG);
     return 0;
    }

   if (1 <= mode)
    {
     fprintf(BCRYPTLOG, "\n -> Key generator function finished.");
     fflush(BCRYPTLOG);
    }

   varinit->PROGRESS = 100;
 
   bclean_string(pass_clear, length, mode);
   bclean_typeint(pass_code, varinit->NB_INDEX,mode);
   if (BCRYPTLOG != stderr) 
    fclose(BCRYPTLOG);
   return 1;
  }
 else
  {
   fprintf (BCRYPTLOG, "\n ERROR.\nPower level '%d' NOT AVAILABLE \n", power);
   fflush(BCRYPTLOG);
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);
   bclean_string(pass_clear, length, mode);
   return 0;
  }

}


/*
 * === LOGIN FUNCTION ===
 *
 * this function checks if the passwd is the same than the one
 * sent in parameter.
 * This is a function for a character string parameter
 */
int
blogin
 (TYPE_INT *code_file, unsigned char *pass_clear, int length, int power,
  int round, int mode, globalvar *varinit)
{

 if (power == 0)
  {
/*
 * eg. : if varinit->KEYLENGTH = 128 bits = 16 characters
 *       I check if the string has, at least, 16 / 2 = 8 characters
 *       Because if the string is smaller it could be weak.
 */
   if (1 <= mode)
    {
     fprintf (BCRYPTLOG,"\n -> Check passwd started.");
     fflush(BCRYPTLOG);
    }

   if ( (length >= (varinit->NB_CHAR / 2) ) &&
    bcrypt_test_passwd (round, code_file, pass_clear, length, mode, 
                        varinit) != 0)
    {
     bclean_string(pass_clear, length, mode);
     if (BCRYPTLOG != stderr)
      fclose(BCRYPTLOG);
     return 1;
    }
   else
    {
     bclean_string(pass_clear, length, mode);
     if (BCRYPTLOG != stderr)
      fclose(BCRYPTLOG);
     return 0;
    }
  }

 fprintf (BCRYPTLOG, "\n ERROR.\nPower level '%d' NOT AVAILABLE \n", power);
 fflush(BCRYPTLOG);
 if (BCRYPTLOG != stderr)
  fclose(BCRYPTLOG);

 return 0;

}


/*
 * === PASSWD CRYPT FUNCTION ===
 *
 * use a string of character in input
 */
int
bpass
 (TYPE_INT *pass_code, unsigned char *pass_clear, int length,int power,
 int round, int mode, globalvar *varinit)
{
 
 if (power == 0)
  {
   if  (2 == mode)
    {
     fprintf(BCRYPTLOG, "\n -> Crypt passwd started.");
     fprintf(BCRYPTLOG, "\n    Length of the passwd typed in BYTES = %d.",
             length);
     fflush(BCRYPTLOG);                            
    }

   if ((varinit->KEYLENGTH / varinit->NB_BITS) < 2)
    {
     if (1 <= mode) 
      {
       fprintf(BCRYPTLOG,"\n ERROR.\nThe KEYLENGTH needs to be at least twice");
       fprintf(BCRYPTLOG,"\nthe size of your integer type, in your case >= %d.",
              (varinit->NB_BITS * 2));
       fflush(BCRYPTLOG);
      }
     return 0;
    }

   if (bcrypt_test_length (pass_clear, length, mode, varinit) == 0)
    {
     bclean_string(pass_clear, length, mode);
     return 0;
    }

   if (bcrypt_transcription (pass_clear, pass_code, mode, varinit) == 0)
    {
     bclean_string(pass_clear, length, mode);
     bclean_typeint(pass_code, varinit->NB_INDEX,mode);
     return 0;
    }

   if (bcrypt_add (pass_code, mode, varinit) == 0)
    {
     bclean_string(pass_clear, length, mode);
     bclean_typeint(pass_code, varinit->NB_INDEX,mode);
     return 0;
    }

   if (bcrypt_swap (pass_code, round, mode, varinit) == 0)
    {
     bclean_string(pass_clear, length, mode);
     bclean_typeint(pass_code, varinit->NB_INDEX,mode);
     return 0;
    }

   if (bcrypt_code (0, 0, pass_code, mode, varinit) == 0)
    {
     bclean_string(pass_clear, length, mode);
     bclean_typeint(pass_code, varinit->NB_INDEX,mode);
     return 0;
    }

   if (2 == mode)
    {
     fprintf(BCRYPTLOG, "\n -> Crypt passwd finished.");
     fflush(BCRYPTLOG);
    }

   bclean_string(pass_clear, length, mode);
   return 1;
 
  }
 else
  {
   fprintf (BCRYPTLOG, "\n ERROR.\nPower level '%d' NOT AVAILABLE \n", power);
   fflush(BCRYPTLOG);
   bclean_string(pass_clear, length, mode);
   return 0;
  }

}


/*
 * === FILE CRYPT FUNCTION ===
 *
 * choice = 0 : crypt
 * choice = 1 : uncrypt
 * choice = 2 : crypt in ASCII mode (only with memory option)
 * choice = 3 : uncrypt in ASCII mode (only with memory option)
 *
 * power = 0  : Seed only
 * power = 1  : Probility Seed
 * power = 2  : Shuffle only
 * power = 3  : Seed and Shuffle
 * power = 4  : Probility Seed and Shuffle
 *
 * if you do not want to use a key file, you have to send a void string in
 * parameter ("") for the "name_key" parameter
 */
RETURN_TYPE
bfile 
 (int choice, char *name_clear, char *name_code, char *name_key,
  unsigned char *pass_param, int length_pass, int power, int round,
  int block_crypt, int block_shuffle, int memory, int mode, globalvar *varinit)
{
 FILE *file_clear, *file_code, *file_key, *file_temp;

 int c, i, j, k, l, shift = 0, shiftfix, tmp_block_crypt;
 int length_file, length_seed, length_mem, tmp_length_mem = 0, length_shuffle;
 int *tab_seed=NULL, *tab_shuffle=NULL, temp_progress = 0, temp_progress_big = 0;
 int prob, tmp_nb, loop_block, pos_crypt, pos_crypt_write;
 int length_file_ascii = 0, temp_pos, temp_pos_write; 
 
 unsigned char *pass_key, *pass_clear;
 char *name_temp="bugstemp.tmp";
 char temp_char, temp_string[50]; 
 TYPE_INT *pass_code, *pass_code_saved, *code_key, *file_mem=NULL, temp_type, temp_i;
 
 int temp_nb, inta, int0, intf;
 int new_shuffle = 0;
 char a[2];

 prob = 0;
 length_mem = 0;
 length_seed =0;
 length_shuffle=0;

 if (1 <= mode)
  {
   switch(choice)
    {
     case 0:
            fprintf(BCRYPTLOG, "\n\n -> CRYPT File");
            break;
     case 1: 
            fprintf(BCRYPTLOG, "\n\n -> DECRYPT File");
            break;
     case 2: 
            fprintf(BCRYPTLOG, "\n\n -> CRYPT File ASCII mode");
            break;
     case 3:
            fprintf(BCRYPTLOG, "\n\n -> DECRYPT File ASCII mode");
            break;
    }
   fflush(BCRYPTLOG);
  }

 if ((0 > power) || (4 < power))
  {
   if (1 <= mode)
    {
     fprintf (BCRYPTLOG, "\n ERROR.\nPower level '%d' NOT AVAILABLE \n", power);
     fflush(BCRYPTLOG);   
    }
   bclean_string(pass_param, length_pass, mode);
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);
   return 0;
  }

 if ((varinit->KEYLENGTH / varinit->NB_BITS) < 2)
  {
   if (1 <= mode)
    {
     fprintf(BCRYPTLOG,"\n ERROR\nThe KEYLENGTH needs to be at least twice");
     fprintf(BCRYPTLOG,"\nthe size of your integer type, in your case >= %d.",
            (varinit->NB_BITS * 2));
     fflush(BCRYPTLOG);
    }
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);
   return 0;
  }

/*
 * I check if I am going to use the probability seed
 */
 if ((1 == power) || (4 == power))
  prob = 1;

/*
 * Check if the source file exists
 */
 file_clear = fopen (name_clear, "rb");
 if (NULL == file_clear)
  {
   if (1 <= mode)
    fprintf(BCRYPTLOG,"\n ERROR.\nSource file does not seem to exist.");

   bclean_string(pass_param, length_pass, mode);
   fflush(BCRYPTLOG);
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);
   return 0;
  }

/*
 * ASCII CRYPT
 */
 if (3 == choice)
  {
   fseek (file_clear, 0, 0);
   i = 0;

   strcpy(temp_string,"\0");

   while ( (feof(file_clear) == 0) && (i == 0))
    {
     fread(&temp_char,1,1,file_clear);

     if (temp_char == '[')
      {
       j = ftell(file_clear);

       fseek(file_clear, j - 1,0); 
       fread(temp_string,1,strlen(BUGS_START), file_clear);

       if (strncmp(temp_string, BUGS_START,strlen(BUGS_START)) == 0)
        i = 1;
       else
        fseek(file_clear, j, 0);
      }
    }

   if (i == 0)
    {
     if ((1 == mode) || (2 == mode))
      {
       fprintf(BCRYPTLOG,"\n ERROR.\n The Source File doesnt look like a BUGS");
       fprintf(BCRYPTLOG,"\n ASCII file. Please make sure you are using the ");
       fprintf(BCRYPTLOG,"\n same compatible version: %s",BUGS_START);
      }
     bclean_string(pass_param, length_pass, mode);
     fflush(BCRYPTLOG);
     if (BCRYPTLOG != stderr)
      fclose(BCRYPTLOG);
     fclose(file_clear);
     return 0;
    }
    
   length_file = 0;
   i = 0;
   while ( (feof(file_clear) == 0) && (i == 0))
    {
     fread(&temp_char,1,1,file_clear);
     if (temp_char != ',')
      length_file = (length_file * 10) + temp_char-'0';
     else
      i = 1;
    }

   temp_pos = ftell(file_clear);
   temp_pos_write = temp_pos;
  }
 else
  {
/*
 * This allows me to know a file's length in BYTES
 */
   fseek (file_clear, 0, 2);
   length_file = ftell (file_clear);
   fseek (file_clear, 0, 0);
   temp_pos = 0;
   temp_pos_write = 0;
  }

/*
 * If no block crypt was set in the parameters this means the user
 * wants to crypt the file as "one big block"
 */
 if (0 == block_crypt)
  block_crypt = length_file;

  if (block_crypt < 0)
   {
    if (1 <= mode)
     {
      if (block_crypt == length_file)
       fprintf(BCRYPTLOG,"\n ERROR.\nThe file size ");
      else
       fprintf(BCRYPTLOG,"\n ERROR.\n The Crypt's block ");
 				 
      fprintf(BCRYPTLOG," has to be >= 0. \n");
     }
    
    bclean_string(pass_param, length_pass, mode);
    fflush(BCRYPTLOG);
    if (BCRYPTLOG != stderr)
     fclose(BCRYPTLOG);
    fclose(file_clear);
    return 0;
   }
 
/*
 * The block shuffle is only used when power > 1
 */
 if (power > 1) 
  {

/*
 * The default block shuffle is = NB_BYTE
 * On a standard PC it is 4, as sizeof(int) = 4 (32 bits)
 */
   if (0 >= block_shuffle)
    block_shuffle = varinit->NB_BYTE;

   if (block_shuffle < varinit->NB_BYTE)
    {
     if (1 <= mode)
      {
       fprintf(BCRYPTLOG,"\n ERROR.\nThe block's shuffle has to be at");
       fprintf(BCRYPTLOG," least >= %d \n", varinit->NB_BYTE);
      }
     bclean_string(pass_param, length_pass, mode);
     fflush(BCRYPTLOG);
     if (BCRYPTLOG != stderr)
      fclose(BCRYPTLOG);
     fclose(file_clear);
	 return 0;
    }

/*
 * For the "shuffle" function to be useful at least 2/3 of the file
 * has to be mixed together
 *
 * Why 6 ? ;o)
 * if there are 6 blocks to shuffle then we can mix 4 of them
 * it's 4 out of 6 ... 4/6 = 2/3
 * So I check if I will have at least 6 blocks to shuffle
 */
   if ( (block_crypt / block_shuffle) < 6)
    {
     if (1 <= mode)
      {
       if (block_crypt == length_file)
        {
         fprintf (BCRYPTLOG,"\n ERROR.\nThe file size should be at least");
         fprintf (BCRYPTLOG," %d bytes with this power level \n",
                 (6*block_shuffle));		
        }
       else
        {
         fprintf (BCRYPTLOG,"\n ERROR.\nThe crypt's block should be at least");
         fprintf (BCRYPTLOG," 6 times bigger than the shuffle's block. \n");
        }
      }

     bclean_string(pass_param, length_pass, mode);
     fflush(BCRYPTLOG);
     if (BCRYPTLOG != stderr)
      fclose(BCRYPTLOG);
     fclose(file_clear);
	 return 0;
    }

/*
 * For algorithmic reasons the block shuffle has to be a multiple
 * of the NB_BYTE you are using
 */ 
   if (((block_shuffle/varinit->NB_BYTE) * varinit->NB_BYTE) != block_shuffle)
    {
     if (1 <= mode)
      {
       fprintf (BCRYPTLOG,"\n ERROR.\nThe Shuffle's block has to be a ");
       fprintf (BCRYPTLOG,"multiple of %d.\n", varinit->NB_BYTE);
       fprintf (BCRYPTLOG,"Which is the number of bytes used by this");
       fprintf (BCRYPTLOG," application for its");
       fprintf (BCRYPTLOG," DEFAULT INTEGER TYPE: TYPE_INT \n");        
      }
	
     bclean_string(pass_param, length_pass, mode);
     fflush(BCRYPTLOG);
     if (BCRYPTLOG != stderr)
      fclose(BCRYPTLOG);
     fclose(file_clear);
	 return 0;
	}
   
  }

/*
 * We allocate memory to our variables
 */
 pass_clear = (unsigned char *) malloc( varinit->NB_CHAR);
 pass_key = (unsigned char *) malloc (varinit->NB_CHAR);
 pass_code = (TYPE_INT *) malloc (varinit->NB_CHAR);
 pass_code_saved = (TYPE_INT *) malloc (varinit->NB_CHAR);
 code_key = (TYPE_INT *) malloc (varinit->NB_CHAR);
 

 if (code_key== NULL) 
  {
   if (1 <= mode)
    {
     fprintf(BCRYPTLOG,"\n ERROR.\n OUT OF MEMORY! (bfile)");
     fflush(BCRYPTLOG);
    }                        
 
       free(pass_clear);
       free(pass_key);
       free(pass_code);
       free(pass_code_saved);
       free(code_key);

       return 0;
  }

/*
 * I check if the user wants to use a key file
 */

 if ( 0 != strcmp(name_key, ""))
  {
   file_key = fopen (name_key, "rb");
   if (NULL != file_key)
    {
     fseek(file_key, 0, 2);
     length_pass=ftell(file_key);
     if (length_pass < varinit->NB_CHAR)
      {
       if (1 <= mode)
        fprintf(BCRYPTLOG,"\n ERROR.\nKey file length < KEYLENGTH.");

       bclean_string(pass_param, length_pass, mode);
       fflush(BCRYPTLOG);
       if (BCRYPTLOG != stderr) 
        fclose(BCRYPTLOG);
       if (file_clear != file_key)
        fclose(file_key);
       fclose(file_clear);

       free(pass_clear);
       free(pass_key);
       free(pass_code);
       free(pass_code_saved);
       free(code_key);

       return 0;
      }

     fclose(file_key);

     if (bcrypt_read_keyfile(pass_clear, name_key, mode, varinit) == 0)
      {
       if (1 <= mode)
        fprintf(BCRYPTLOG,"\n ERROR.\nRead key file failed.");

       bclean_string(pass_param, length_pass, mode);
       fflush(BCRYPTLOG);
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);
       fclose(file_clear);
 
       free(pass_clear);  
       free(pass_key);
       free(pass_code);
       free(pass_code_saved);
       free(code_key);

       return 0;
      }
    }
  }
 else
  {

/*
 * If we do not use a keyfile then a password must have been sent
 * in the parameters
 */
   memcpy(pass_clear, pass_param, length_pass);
   bclean_string(pass_param, length_pass, mode);

   if (varinit->NB_CHAR < length_pass)
    {
     if (1 <= mode)
      {
       fprintf (BCRYPTLOG,"\n ERROR.\nWrong password length specified,");
       fprintf (BCRYPTLOG," should not be > %d\n", varinit->NB_CHAR); 
       bclean_string(pass_param, length_pass, mode);
       fflush(BCRYPTLOG);
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);
       fclose(file_clear);

       free(pass_clear);
       free(pass_key);
       free(pass_code);
       free(pass_code_saved);
       free(code_key);
     
       return 0;
      }
    }
  }

/*
 * The password's length sent as a parameter has to be
 * at least half of the keylength
 */

 if ( length_pass < (varinit->NB_CHAR / 2) )
  {
   if (1 == mode)
    {
     fprintf (BCRYPTLOG,"\n ERROR.\nWrong password/file length :");
     fprintf (BCRYPTLOG," %d. It has to be at least: %d.",
              length_pass, varinit->NB_CHAR);
     fflush(BCRYPTLOG);
    }

   bclean_string(pass_param, varinit->NB_CHAR, mode);
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);
   fclose(file_clear);

   free(pass_clear);
   free(pass_key);
   free(pass_code);
   free(pass_code_saved);
   free(code_key);
   
   return 0;
  }

/*
 * We try to create the destination file
 */
 file_code = fopen (name_code, "w+b");
 if (file_code == NULL)
 {
  if (1 <= mode)
   {
    fprintf (BCRYPTLOG, "\n ERROR.\nCannot open destination file.");
    fflush(BCRYPTLOG);
   } 

  bclean_string(pass_clear, varinit->NB_CHAR, mode);
  if (BCRYPTLOG != stderr) fclose(BCRYPTLOG);
  fclose(file_clear);
 
  free(pass_clear);
  free(pass_key);
  free(pass_code);
  free(pass_code_saved);
  free(code_key);
  
  return 0;
 }

/*
 * If we use the probability seed will add varinit->NB_CHAR
 * to the crypt's block as we wil be using a random number
 * that we need to crypt and save to be able to revover it
 * when decrypting.
 * So we mix the random number with a key and add it to the block
 * crypt
 */
 if (1 == prob)
  {
   if ((0 == choice) || (choice == 2))
    {

/*
 * Do we crypt the file by blocks ?
 * if so tmp_nb is the number of loop we need to do
 * to crypt the whole file
 */
     tmp_nb = length_file/block_crypt;
     if ( (tmp_nb * block_crypt) < length_file)
      tmp_nb++;

     block_crypt += varinit->NB_CHAR;
    }
   else
    {
     if (block_crypt != length_file)
      block_crypt += varinit->NB_CHAR;

/* 
 * if we decrypt we need to add varinit->NB_CHAR to the block crypt
 * before we set the tmp_nb.
 * this is because in this case the length_file would already
 * be bigger by varinit->NB_CHAR 
 */
     tmp_nb = length_file/block_crypt;
     if ( (tmp_nb * block_crypt) < length_file)
      tmp_nb++;
    }

  }
 else
  {

/*
 * Do we crypt the file by blocks ?
 * if so tmp_nb is the number of loop we need to do
 * to crypt the whole file
 */
   tmp_nb = length_file/block_crypt;
   if ( (tmp_nb * block_crypt) < length_file)
    tmp_nb++;
  }

/*
 * file_mem will receive the block to crypt
 */
 if (1 == memory) 
  {
   length_mem = block_crypt / varinit->NB_BYTE;
   if ( (length_mem * varinit->NB_BYTE) < block_crypt )
    length_mem++;

   file_mem = (TYPE_INT *) malloc(length_mem * varinit->NB_BYTE);

   if (NULL == file_mem)
    {
     if (1 <= mode)
      {
       fprintf(BCRYPTLOG,"\n ERROR.\nNot enough memory to allocate for");
       fprintf(BCRYPTLOG," the file you want to crypt.");
       fprintf(BCRYPTLOG,"\n Please use the hardisk method to crypt rather");
       fprintf(BCRYPTLOG," than the memory method.");
       fflush(BCRYPTLOG);
      }

     bclean_string(pass_clear, varinit->NB_CHAR, mode);
     if (BCRYPTLOG != stderr)
      fclose(BCRYPTLOG);
     if (file_clear != file_code)
      fclose(file_clear);
     fclose(file_code);

     free(pass_clear);
     free(pass_key);
     free(pass_code);
     free(pass_code_saved);
     free(code_key);

     return 0;
    }

/*
 * This is because the last block can be smaller than a TYPE_INT
 */
   file_mem[length_mem -1] = 0;

   if (2 == mode)
    {
     fprintf(BCRYPTLOG, "\n    MEMORY METHOD SELECTED.");
     fflush(BCRYPTLOG);
    }
  }
 else
  {
   if ((2 == choice) || (3 == choice))
    {
     if (1 <= mode)
      {
       fprintf(BCRYPTLOG,"\n ERROR.\nYou need to be in MEMORY mode if");
       fprintf(BCRYPTLOG," you want to use the ASCII method.");
       fflush(BCRYPTLOG);
      }

     bclean_string(pass_clear, varinit->NB_CHAR, mode);
     if (BCRYPTLOG != stderr)
      fclose(BCRYPTLOG);
     if (file_clear != file_code)
	  fclose(file_clear);
     fclose(file_code);

     free(pass_clear);
     free(pass_key);
     free(pass_code);
     free(pass_code_saved);
     free(code_key);

     return 0;
    }
         
   if (2 == mode)
    {
     fprintf(BCRYPTLOG, "\n    HARD-DISK METHOD SELECTED.");
     fflush(BCRYPTLOG);
    }
  }

/*
 * we find the number of filter needed to the seed process
 */
 if (2 != power)
  {
   length_seed = (block_crypt/varinit->NB_CHAR);
   if ((length_seed * varinit->NB_CHAR) < block_crypt)
    length_seed++;

   tab_seed = (int *) malloc (length_seed * sizeof(int));
	
   if (NULL == tab_seed) 
    {
     if (1 <= mode)
      {
       fprintf (BCRYPTLOG,"\n ERROR.\nNot Enough memory to allocate for");
       fprintf (BCRYPTLOG," the SEED sequence array.");
       fflush(BCRYPTLOG);
      } 
     if (BCRYPTLOG != stderr)
      fclose(BCRYPTLOG);
     if (file_clear != file_code)
	  fclose(file_clear);
     fclose(file_code);

     free(pass_clear);
     free(pass_key);
     free(pass_code);
     free(pass_code_saved);
     free(code_key);

     return 0;
    }
  }

/*
 * Now we create the first key from the passwd
 */
 if (bcrypt_test_length (pass_clear, length_pass, mode, varinit) == 0)
  {
   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   if (file_clear != file_code) 
    fclose (file_clear);
   fclose (file_code);
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);

   free(pass_clear);  
   free(pass_key);
   free(pass_code);
   free(pass_code_saved);
   free(code_key); 

   return 0;
  }

 length_pass = varinit->NB_CHAR;

 if (bcrypt_transcription (pass_clear, pass_code, mode, varinit) == 0)
  {
   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   bclean_typeint(pass_code, varinit->NB_INDEX,mode);
   if (file_clear != file_code)
    fclose (file_clear);
   fclose (file_code);
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);

   free(pass_clear);  
   free(pass_key);
   free(pass_code);
   free(pass_code_saved);
   free(code_key); 

   return 0;
  }

 if (bcrypt_add (pass_code, mode, varinit) == 0)
  {
   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   bclean_typeint(pass_code, varinit->NB_INDEX,mode);
   if (file_clear != file_code)
   fclose (file_clear);
   fclose (file_code);
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);

   free(pass_clear);  
   free(pass_key);
   free(pass_code);
   free(pass_code_saved);
   free(code_key); 

   return 0;
  }

 if (bcrypt_swap (pass_code, round, mode, varinit) == 0)
  {
   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   bclean_typeint(pass_code, varinit->NB_INDEX,mode);
   if (file_clear != file_code)
    fclose (file_clear);
   fclose (file_code);
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);

   free(pass_clear);  
   free(pass_key);
   free(pass_code);
   free(pass_code_saved);
   free(code_key); 

   return 0;
  }

/*
 * Now that we now the block's crypt we can find how many block's 
 * shuffle there are in a block's crypt
 * We need to initialise tab_shuffle after we generated the first KEY 
 * in case we want to "dynamicaly" change the value of trhe shuffle block.
 */
 if (power > 1)
  {
   if ((varinit->MISC & BMASK_SHUFFLE) == BMASK_SHUFFLE)
    {
     if (2 == mode)
      {
       fprintf(BCRYPTLOG, "\n     Dynamic Shuffle Flag Detected.");
       fflush(BCRYPTLOG);
      }
     i = ((unsigned int)pass_code[1%varinit->NB_INDEX])%varinit->NB_INDEX;

     if (block_shuffle < varinit->NB_BITS)
      new_shuffle = ((unsigned int)pass_code[i])%varinit->NB_BITS;  
     else
      new_shuffle = ((unsigned int)pass_code[i])%block_shuffle;  

     new_shuffle = new_shuffle + block_shuffle;

     new_shuffle = (new_shuffle/varinit->NB_BYTE) * varinit->NB_BYTE;

     while( ((block_crypt / new_shuffle) < 6) && (new_shuffle > 0))
      new_shuffle = new_shuffle - varinit->NB_BYTE;

     if (new_shuffle < varinit->NB_BYTE)
      {    
       if ((1 == mode) || (2 == mode))
        {
         fprintf (BCRYPTLOG,"\n WARNING.\n Couldn't assign a dynamic value");
         fprintf (BCRYPTLOG," to the block shuffle. \n");
        }
      }
     else
      {
       if (2 == mode)
        {
         fprintf(BCRYPTLOG,"\n     Old block Shuffle size: '%d'",block_shuffle);
         fprintf(BCRYPTLOG,"\n     New block SHUFFLE size: '%d'",new_shuffle);
         fflush(BCRYPTLOG);
        }
       block_shuffle = new_shuffle;
      }
    }

   length_shuffle = (block_crypt/block_shuffle);
   if ( (length_shuffle * block_shuffle) < block_crypt )
    length_shuffle++;

   tab_shuffle = (int *) malloc (length_shuffle * sizeof(int));
	
   if (tab_shuffle == NULL) 
    {
     if ((1 == mode) || (2 == mode))
      {
       fprintf (BCRYPTLOG,"\n ERROR.\nNot Enough memory to allocate for");
       fprintf (BCRYPTLOG," the SHUFFLE sequence array.");
       fflush(BCRYPTLOG);
      } 
     if (BCRYPTLOG != stderr)
      fclose(BCRYPTLOG);
     if (file_clear != file_code)
	  fclose(file_clear);
     fclose(file_code);

     bclean_string(pass_clear, varinit->NB_CHAR, mode);
     bclean_typeint(pass_code, varinit->NB_INDEX,mode);
     free(pass_clear);  
     free(pass_key);
     free(pass_code);
     free(pass_code_saved);
     free(code_key); 
     free(tab_shuffle); 

     return 0;
    }
  }

if (varinit->PROGRESS<80)
    varinit->PROGRESS = varinit->PROGRESS+20;

/*
 * We do not call bcrypt_code because we do not want to add a 
 * random number
 *
 * NOW WE CRYPT !
 */
 if ((0 == choice) || (2 == choice))
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG, "\n\n => Crypting file in progress...");
     fprintf (BCRYPTLOG, "\n    Source File Length                 : %d.",
              length_file);
     fprintf (BCRYPTLOG, "\n    Block Crypt (BC)                   : %d.",
              block_crypt);
     fprintf (BCRYPTLOG, "\n    Nb of BC for this file             : %d.",
              tmp_nb);
     fprintf (BCRYPTLOG, "\n    Nb of SEED filters/BC              : %d.",
              length_seed);
     fprintf (BCRYPTLOG, "\n    Block Shuffle (BS)                 : %d.",
              block_shuffle);
     fprintf (BCRYPTLOG, "\n    Nb of BS/BC                        : %d.",
              length_shuffle);
     fprintf (BCRYPTLOG, "\n    Please wait... \n");
     fflush(BCRYPTLOG);
    }

/*
 * If we only do a shuffle we need to create the destination 
 * file first.
 * We don't need that when we do the seed because the seed is done 
 * first, and the seed works with a SRC and DST file.
 * The shuffle only works with a DST file and I do not want
 * to change the original file
 */
   if (2 == power) 
    {
     fseek(file_code,0,0);
     fseek(file_clear,0,0);
	
     while( (c = getc(file_clear)) != EOF)
      putc(c, file_code);
	
     fseek(file_code,0,0);
     fseek(file_clear,0,0);

/*
 * The pass_code will change in bcrypt_file_seed.
 * I need to save the current pass_code value as I will use it in 
 * bcrypt_shuffle
 * And when I decrypt a file I start to unshuffle, so it's quicker if I save
 * the first pass_code value and use it as well with bcrypt_shuffle.
 * Otherwise, when I decrypt a file I would have to generate all the pass_code
 * generated in file_seed first !
 * The file_seed function used anyway the next value of pass_code first.
 */
     memcpy(pass_code_saved, pass_code, varinit->NB_CHAR);
    }

   if (1 == prob)
    tmp_block_crypt = block_crypt - varinit->NB_CHAR;
   else	
    tmp_block_crypt = block_crypt;

   if (1 == memory)
    tmp_length_mem = length_mem;

   if (1 < tmp_nb)
    temp_progress = (80 / tmp_nb);

   if (0 == temp_progress)
    { 
     temp_progress_big = 1;
     temp_progress= 0;
    }

   if (2 == choice)
    {
     if (1 == prob)
      length_file_ascii = length_file + (varinit->NB_CHAR * tmp_nb);
     else
      length_file_ascii = length_file;
    }
/*
 * We start the loop to crypt all the blocks of the file
 */
   for (loop_block = 0; loop_block < tmp_nb; loop_block++)
    {
     pos_crypt = tmp_block_crypt * loop_block;
     pos_crypt_write = pos_crypt + (prob * (loop_block * varinit->NB_CHAR));

/*
 * If the block to crypt is bigger than the end of the file
 */
     if ((pos_crypt + tmp_block_crypt) > length_file) 
      {
       block_crypt = length_file - pos_crypt;

       if (1 == memory)
        {
         fseek (file_clear, pos_crypt, 0);
         bcrypt_fread_int(file_mem, 1, block_crypt, file_clear,varinit,mode);
        }

       tmp_block_crypt = block_crypt;

       if (1 == prob)
        block_crypt += varinit->NB_CHAR;
		
       if (1 == memory)
        {
         tmp_length_mem = block_crypt / varinit->NB_BYTE;
         if ( (tmp_length_mem * varinit->NB_BYTE) < block_crypt )
          tmp_length_mem++;
        }

       if (1 < power)
        {
         length_shuffle = (block_crypt / block_shuffle);
         if ((length_shuffle * block_shuffle) < block_crypt)
          length_shuffle++;
        }

       if (2 != power)
        {
         length_seed = (block_crypt / varinit->NB_CHAR);
         if ((length_seed * varinit->NB_CHAR) < block_crypt)
          length_seed++;
        }
      }

     if (1 == memory)
      {
       fseek (file_clear, pos_crypt, 0);
       bcrypt_fread_int (file_mem, 1, block_crypt, file_clear,varinit,mode);
      }

     if (2 != power)
      {
       for (i=0; i < varinit->NB_INDEX; i++) 
        pass_code_saved[i] = pass_code[i];
      }

/*
 * Seed funtion call
 */
     if ( (0 == power) || (3 == power) )
      {

/*
 * First part of the crypt process
 * we "seed" the file
 */
       if (0 == memory)
        {
         if (bcrypt_file_seed (file_clear, file_code, tab_seed, length_seed,
                               pass_code, round, block_crypt, pos_crypt, mode,
                               varinit) == 0)
          {
           bclean_string(pass_clear, varinit->NB_CHAR, mode);
           bclean_typeint(pass_code, varinit->NB_INDEX,mode);
           bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
           if (BCRYPTLOG != stderr)
            fclose(BCRYPTLOG);
           if (file_clear != file_code)
		    fclose(file_clear);
           fclose(file_code);

           free(pass_clear);  
           free(pass_key);
           free(pass_code);
           free(pass_code_saved);
           free(code_key); 
  
           return 0;
          }
        }
       else
        {
         if (bcrypt_mem_seed (file_mem, tmp_length_mem, tab_seed, length_seed,
                              pass_code, round, mode, varinit) == 0)
          {
           bclean_string(pass_clear, varinit->NB_CHAR, mode);
           bclean_typeint(pass_code, varinit->NB_INDEX,mode);
           bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
	
           bclean_typeint(file_mem, length_mem,mode);
           free(file_mem);
	
           if (BCRYPTLOG != stderr)
            fclose(BCRYPTLOG);
           if (file_clear != file_code)
		    fclose(file_clear);
           fclose(file_code);

           free(pass_clear);  
           free(pass_key);
           free(pass_code);
           free(pass_code_saved);
           free(code_key); 
  
           return 0;
          }

         if (0 == power)
          {
           if (2 == choice)
            {
             fseek (file_code, temp_pos, 0);
             temp_pos_write = temp_pos;

             if (0 == loop_block)
              fprintf(file_code,"%s%d,",BUGS_START,length_file_ascii);

             k = block_crypt / varinit->NB_BYTE;
             if ((k * varinit->NB_BYTE) < block_crypt)
              k++;
        
             l=0;
             i=0;
             shiftfix=varinit->NB_BITS - 8;

             do
              {
               if (l == 0)
                shift = shiftfix;
               else
                shift = shift - 8;

			   sprintf(a,"%2X",(int)((file_mem[i] << shift) >> shiftfix));
 
               if (a[0] == ' ')
                fprintf(file_code,"0%c",a[1]);
               else
                fprintf(file_code,"%c%c",a[0],a[1]);

               l++;
               if (l == varinit->NB_BYTE)
                {
                 l = 0;
                 i++;
                }
              }
             while (i<k);
	  		                              
             temp_pos = ftell(file_code);

            }
           else
            {

             fseek (file_code, pos_crypt_write, 0);
             bcrypt_fwrite_int (file_mem, 1, block_crypt, file_code, varinit,
                                mode);

            }
          }
        }
      }
               

/*
 * Probability Seed function call
 */
     if ( (1 == power) || (4 == power) )
      {

/*
 * First part of the crypt process
 * we "seed" the file
 *
 * We translate the long integer from pass_code into some characters
 * in the string pass_clear
 */
       l=0;
       k=0;
       i=0;
       shiftfix=varinit->NB_BITS - 8;

       do
        {
         if (l == 0) 
          shift = shiftfix;
         else
          shift = shift - 8;

         pass_key[i] = (int)((pass_code[k] << shift) >> shiftfix);

         l++;
         if (l == varinit->NB_BYTE)
          {
           l = 0;
           k++;
          }
         i++;
        }
       while (k < varinit->NB_INDEX);

/*
 * We are going to generate a passwd from the passwd's crypt result
 * using a random number
 */
       if (bpass (code_key, pass_key, length_pass, 0, round, mode,varinit) == 0)
        {
         bclean_string(pass_clear, varinit->NB_CHAR, mode);
         bclean_string(pass_key, varinit->NB_CHAR, mode);
         bclean_typeint(pass_code, varinit->NB_INDEX,mode);
         if (file_clear != file_code)
		  fclose (file_clear);
         fclose (file_code);
/*
 * I do not close BCRYPTLOG because It has been already done
 * in bpass function.
 */
         free(pass_clear);  
         free(pass_key);
         free(pass_code);
         free(pass_code_saved);
         free(code_key); 
  
         return 0;
        }

       if (0 == memory)
        {
         if (bcrypt_file_seed_prob (choice, file_clear, file_code, tab_seed,
             length_seed, pass_code, code_key, round, tmp_block_crypt,
             pos_crypt, pos_crypt_write, mode, varinit) == 0)
          {
           bclean_string(pass_clear, varinit->NB_CHAR, mode);
           bclean_typeint(pass_code, varinit->NB_INDEX,mode);
           bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
           if (BCRYPTLOG != stderr)
            fclose(BCRYPTLOG);
           if (file_clear != file_code)
		    fclose(file_clear);
           fclose(file_code);
  
           free(pass_clear);  
           free(pass_key);
           free(pass_code);
           free(pass_code_saved);
           free(code_key); 
  
           return 0;
          }
        }
       else
        {
         if (bcrypt_mem_seed_prob (choice, file_mem, tmp_length_mem, tab_seed,
                                   length_seed, pass_code, code_key, round,
                                   mode, varinit) == 0)
          {
           bclean_string(pass_clear, varinit->NB_CHAR, mode);
           bclean_typeint(pass_code, varinit->NB_INDEX,mode);
           bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
	
           bclean_typeint(file_mem, length_mem,mode);
           free(file_mem);
 	
           if (BCRYPTLOG != stderr)
            fclose(BCRYPTLOG);
           if (file_clear != file_code)
		    fclose(file_clear);
           fclose(file_code);

           free(pass_clear);  
           free(pass_key);
           free(pass_code);
           free(pass_code_saved);
           free(code_key); 
  
           return 0;
          }

         if (1 == power)
          {
           if (2 == choice)
            {
             fseek (file_code, temp_pos, 0);
             temp_pos_write = temp_pos;
 
             if (0 == loop_block)
             fprintf(file_code,"%s%d,",BUGS_START,length_file_ascii);

             k = block_crypt / varinit->NB_BYTE;
             if ((k * varinit->NB_BYTE) < block_crypt) k++;

             l=0;
             i=0;
             shiftfix=varinit->NB_BITS - 8;
        
             do
              {
               if (l == 0)
                shift = shiftfix;
               else
                shift = shift - 8;

               sprintf(a,"%2X",(int)((file_mem[i] << shift) >> shiftfix));
 
               if (a[0] == ' ')
                fprintf(file_code,"0%c",a[1]);
               else
                fprintf(file_code,"%c%c",a[0],a[1]);

               l++;
               if (l == varinit->NB_BYTE)
                {
                 l = 0;
                 i++;
                }
              }
             while (i<k);

             temp_pos = ftell(file_code);
            }
           else
            {
             fseek (file_code, pos_crypt_write, 0);
             bcrypt_fwrite_int (file_mem, 1, block_crypt, file_code, varinit,
                                mode);
            }
          }
        }
      }

     if (1 < tmp_nb) 
      {
       if (0 == temp_progress_big)
        varinit->PROGRESS = varinit->PROGRESS + temp_progress;
       else
        {
         if (5000 <= temp_progress)
          {
           temp_progress = 0;
           varinit->PROGRESS++;
          }
         else
          temp_progress++;
        }
      }
     else
      varinit->PROGRESS = varinit->PROGRESS + 50;
		
/*
 * Shuffle function call
 */
     if (1 < power)
      {
 /*
  * Second part of the crypt process
  * We shuffle the blocks of the file
  */
       if (0 == memory)
        {
         if (bcrypt_file_shuffle (file_code, tab_shuffle, length_shuffle,
                                  pass_code_saved, round, block_crypt,
                                  block_shuffle, pos_crypt_write, mode,
                                  varinit) == 0)
          {
           bclean_string(pass_clear, varinit->NB_CHAR, mode);
           bclean_typeint(pass_code, varinit->NB_INDEX,mode);
           bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
           if (BCRYPTLOG != stderr)
            fclose(BCRYPTLOG);
           if (file_clear != file_code)
		    fclose(file_clear);
           fclose(file_code);

           free(pass_clear);  
           free(pass_key);
           free(pass_code);
           free(pass_code_saved);
           free(code_key); 
           free(tab_shuffle); 

           return 0;
          }
        }
       else
        {
         if (bcrypt_mem_shuffle (file_mem, tmp_length_mem, tab_shuffle,
                                 length_shuffle, pass_code_saved, round,
                                 block_shuffle, mode, varinit) == 0)
          {
           bclean_string(pass_clear, varinit->NB_CHAR, mode);
           bclean_typeint(pass_code, varinit->NB_INDEX,mode);
           bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
           bclean_typeint(file_mem, length_mem,mode);
           free(file_mem);

           if (BCRYPTLOG != stderr)
            fclose(BCRYPTLOG);
           if (file_clear != file_code)
            fclose(file_clear);
           fclose(file_code);

           free(pass_clear);  
           free(pass_key);
           free(pass_code);
           free(pass_code_saved);
           free(code_key); 
           free(tab_shuffle); 

           return 0;
 
          }

         if (2 == choice)
          {
           fseek (file_code, temp_pos_write, 0);
           if (0 == loop_block)
            fprintf(file_code,"%s%d,",BUGS_START,length_file_ascii);

           k = block_crypt / varinit->NB_BYTE;
           if ((k * varinit->NB_BYTE) < block_crypt)
            k++;

           l=0;
           i=0;
           shiftfix=varinit->NB_BITS - 8;
        
           do
            {
             if (l == 0)
              shift = shiftfix;
             else
              shift = shift - 8;

             sprintf(a,"%2X",(int)((file_mem[i] << shift) >> shiftfix));

             if (a[0] == ' ')
              fprintf(file_code,"0%c",a[1]);
             else
              fprintf(file_code,"%c%c",a[0],a[1]);

             l++;
             if (l == varinit->NB_BYTE)
              {
               l = 0;
               i++;
              }
            }
           while (i<k);
  
           temp_pos_write = ftell(file_code);
          }
         else
          {
           fseek (file_code, pos_crypt_write, 0);
           bcrypt_fwrite_int (file_mem, 1, block_crypt, file_code,varinit,mode);
          }
        }
      }	

     if (1 < tmp_nb)
      {
       if (0 == temp_progress_big)
        varinit->PROGRESS = varinit->PROGRESS + temp_progress;
       else
        {
         if (5000 <= temp_progress)
          {
           temp_progress = 0;
           varinit->PROGRESS++;
          }
         else
          temp_progress++;
        }
      }
     else
      varinit->PROGRESS = 100;
    }	
        
   if (2 == choice)
    fprintf(file_code,"%s",BUGS_END);

   if ((1 == mode) || (2 == mode))
    {
     if (choice == 0)
      {
       fprintf(BCRYPTLOG, "    Done. \n -> CRYPT file function Finished.\n");
       fflush(BCRYPTLOG);
      }
    }
   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   bclean_typeint(pass_code, varinit->NB_INDEX,mode);
   bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);

   if (1 == memory)
    {
     bclean_typeint(file_mem, length_mem, mode); 
     free(file_mem);
    }

   varinit->PROGRESS = 100;
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);
   fclose(file_clear);
   fclose(file_code);

   free(pass_clear);  
   free(pass_key);
   free(pass_code);
   free(pass_code_saved);
   free(code_key); 
   if (2 <= power)
    free(tab_shuffle); 

   return 1;
  }
 else
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG, "\n\n => DEcrypting file in progress...");

     fprintf (BCRYPTLOG, "\n    Source File Length                 : %d.",
              length_file);
     fprintf (BCRYPTLOG, "\n    Block Crypt (BC)                   : %d.",
              block_crypt);
     fprintf (BCRYPTLOG, "\n    Nb of BC for this file             : %d.",
              tmp_nb);
     fprintf (BCRYPTLOG, "\n    Nb of SEED filters/BC              : %d.",
              length_seed);
     fprintf (BCRYPTLOG, "\n    Block Shuffle (BS)                 : %d.",
              block_shuffle);
     fprintf (BCRYPTLOG, "\n    Nb of BS/BC                        : %d.",
              length_shuffle);
     fprintf (BCRYPTLOG, "\n    Please wait... \n");
     fflush(BCRYPTLOG);
    }

   if (2 == power)
    for (i=0; i < varinit->NB_INDEX; i++)
     pass_code_saved[i] = pass_code[i];

   file_temp = file_code;

/*
 * We need to create a tempory file if we use the shuffle function
 */
   if ((1 < power) && (0 == memory))
    {
     if (1 == prob) 
      {
       if (1 <= mode)
        {
         fprintf (BCRYPTLOG, "\n    Creating Tempory file: %s.",name_temp);
         fflush(BCRYPTLOG);
        } 

       file_temp = fopen (name_temp, "w+b");
       if (file_temp == NULL)
        {
         if (1 <= mode)
          {
           fprintf(BCRYPTLOG,"\n ERROR.\nCannot open TEMPORY destination");
           fprintf(BCRYPTLOG,"file: %s.",name_temp);
           fflush(BCRYPTLOG);
          } 
	
         bclean_string(pass_clear, varinit->NB_CHAR, mode);
         if (BCRYPTLOG != stderr) fclose(BCRYPTLOG);
         fclose(file_clear);

         free(pass_clear);  
         free(pass_key);
         free(pass_code);
         free(pass_code_saved);
         free(code_key); 

         return 0;
        }
      }

     fseek(file_temp,0,0);
     fseek(file_clear,0,0);
		
     while( (c = getc(file_clear)) != EOF)
      putc(c, file_temp);
		
     fseek(file_temp,0,0);
     fseek(file_clear,0,0);

     fclose(file_clear);
     file_clear = file_temp;
    }

   if (1 < tmp_nb)
    temp_progress = (80 / tmp_nb);

   if (0 == temp_progress)
    {
     temp_progress_big = 1;
     temp_progress = 0;
    }
   else
    temp_progress = 1;

/*
 * We start the loop to decrypt all the blocks of the file
 */
   for (loop_block = 0; loop_block < tmp_nb; loop_block++)
    {
     pos_crypt = block_crypt * loop_block;
     pos_crypt_write = pos_crypt - (prob * (loop_block * varinit->NB_CHAR));

/*
 * If the block to crypt is bigger than the end of the file
 */
     if ((pos_crypt + block_crypt) > length_file) 
      {
       block_crypt = length_file - pos_crypt;


       if (1 == memory)
        {
         tmp_length_mem = block_crypt / varinit->NB_BYTE;
         if ( (tmp_length_mem * varinit->NB_BYTE) < block_crypt )
          tmp_length_mem++;
        }

       if (1 < power)
        {
         length_shuffle = (block_crypt / block_shuffle);
         if ((length_shuffle * block_shuffle) < block_crypt) length_shuffle++;
        }

       if (2 != power)
        {
         length_seed = (block_crypt / varinit->NB_CHAR);
         if ((length_seed * varinit->NB_CHAR) < block_crypt) length_seed++;

         if ((length_seed < 2) && (1 == prob))
          {
           if (1<=mode)
            {
             fprintf(BCRYPTLOG, "\n ERROR.\nThis file cannot be decrypted with these parameters\n");
             fflush(BCRYPTLOG);

              bclean_string(pass_clear, varinit->NB_CHAR, mode);
              bclean_typeint(pass_code, varinit->NB_INDEX,mode);
              if (BCRYPTLOG != stderr)
               fclose(BCRYPTLOG);
              if (file_clear != file_code)
               fclose(file_clear);
              fclose(file_code);
 
              free(pass_clear);  
              free(pass_key);
              free(pass_code);
              free(pass_code_saved);
              free(code_key); 
  
              return 0;
            }
          }
        }
      }
     else
      if  (1 == memory) tmp_length_mem = length_mem;

      if (1 == memory)
       {
        if (3 == choice)
         {
          fseek (file_clear, temp_pos, 0);
          k = block_crypt / varinit->NB_BYTE;
          if ((k * varinit->NB_BYTE) < block_crypt)
           k++;

          temp_type = 0;
          temp_nb = 0;
          inta = 'A';
          int0 = '0';
          intf = 'F';
          i = 0;

          while ( (feof(file_clear) == 0) && (i < k))
           {
            if (temp_nb < varinit->NB_BYTE)
             {	
              j = 0;	     
              while ((feof(file_clear) == 0) && (j < 2))
               {
                fread(&temp_char,1,1,file_clear);
                if (((temp_char >= inta) && (temp_char <= intf)) ||
                   ((temp_char >= int0) && (temp_char < (int0+10))) )
                 {
                  a[j] = temp_char;
                  j++;
                 }
               }	
              temp_nb++;
		     
              if ((a[0] < (int0 + 10)) && (a[0] >= int0))
               temp_i = a[0] - int0;
              else
               temp_i = 10 + a[0] - inta;
			
              temp_i = temp_i*16;
			
              if ( (a[1] < (int0 + 10)) && (a[1] >= int0))
               temp_i = temp_i + a[1] - int0;
              else
               temp_i = temp_i + 10 + a[1] - inta;
			
              temp_i = temp_i << ((temp_nb - 1) * 8);
              temp_type |= temp_i;
             }
            else
             {
              file_mem[i] = temp_type;
              temp_type = 0;
              temp_nb = 0;
              i++;
             }
           }

          temp_pos = ftell(file_clear);
         }
        else
         {
          fseek (file_clear, pos_crypt, 0);             
          bcrypt_fread_int (file_mem, 1, block_crypt, file_clear,varinit,mode);
         }
       }

      if (2 != power)
       {
        for (i=0; i < varinit->NB_INDEX; i++) 
        pass_code_saved[i] = pass_code[i];
       }

/*
 * UnShuffle function call
 */
      if (1 < power)
       {
        if (0 == memory)
         {
          if(bcrypt_file_unshuffle (file_temp, tab_shuffle, length_shuffle,
                                    pass_code_saved, round, block_crypt,
                                    block_shuffle, pos_crypt, mode,
                                    varinit) == 0)
           {
            bclean_string(pass_clear, varinit->NB_CHAR, mode);
            bclean_typeint(pass_code, varinit->NB_INDEX,mode);
            if (BCRYPTLOG != stderr)
             fclose(BCRYPTLOG);
            if (file_clear != file_code)
             fclose(file_clear);
            fclose(file_code);

            free(pass_clear);  
            free(pass_key);
            free(pass_code);
            free(pass_code_saved);
            free(code_key); 
            free(tab_shuffle); 

            return 0;
           }
         }
        else
         {
          if (bcrypt_mem_unshuffle (file_mem, tmp_length_mem, tab_shuffle,
                                   length_shuffle, pass_code_saved, round,
                                   block_shuffle, mode, varinit) == 0)
           {
            bclean_string(pass_clear, varinit->NB_CHAR, mode);
            bclean_typeint(pass_code, varinit->NB_INDEX,mode);
	
            bclean_typeint(file_mem, length_mem,mode);
            free(file_mem);
	
            if (BCRYPTLOG != stderr)
             fclose(BCRYPTLOG);
            if (file_clear != file_code)
             fclose(file_clear);
            fclose(file_code);

            free(pass_clear);  
            free(pass_key);
            free(pass_code);
            free(pass_code_saved);
            free(code_key); 
            free(tab_shuffle); 

            return 0;
           }

/* 
 * If we only unshuffle the file we need to write the result
 */
          if ( 2 == power)
		   {
            fseek (file_code, pos_crypt_write, 0);
            bcrypt_fwrite_int(file_mem, 1, block_crypt, file_code,varinit,mode);
           }
         }
       }

      if (1 < tmp_nb)
       {
        if (0 == temp_progress_big)
         varinit->PROGRESS = varinit->PROGRESS + temp_progress;
        else
         {
          if (5000 <= temp_progress)
           {
            temp_progress = 0;
            varinit->PROGRESS++;
           }
          else
           temp_progress++;
         }
       }
      else
       varinit->PROGRESS = varinit->PROGRESS + 50;

/*
 * Seed function call
 */
      if ( (0 == power) || (3 == power) )
       {
/*
 * Second part of the DEcrypt process
 * we "seed" the file
 */
        if (0 == memory)
         {
          if (bcrypt_file_seed (file_clear, file_code, tab_seed,
                               length_seed, pass_code, round, block_crypt,
                               pos_crypt, mode, varinit) == 0)
           {
            bclean_string(pass_clear, varinit->NB_CHAR, mode);
            bclean_typeint(pass_code, varinit->NB_INDEX,mode);
            bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
            if (BCRYPTLOG != stderr)
             fclose(BCRYPTLOG);
            if (file_clear != file_code)
             fclose(file_clear);
            fclose(file_code);

            free(pass_clear);  
            free(pass_key);
            free(pass_code);
            free(pass_code_saved);
            free(code_key); 

            return 0;
           }
         }
	    else
         {
          if(bcrypt_mem_seed (file_mem, tmp_length_mem, tab_seed,length_seed,
                              pass_code, round, mode, varinit) == 0)
           {
            bclean_string(pass_clear, varinit->NB_CHAR, mode);
            bclean_typeint(pass_code, varinit->NB_INDEX,mode);
            bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
            bclean_typeint(file_mem, length_mem,mode);
            free(file_mem);
            if (BCRYPTLOG != stderr)
             fclose(BCRYPTLOG);
            if (file_clear != file_code)
             fclose(file_clear);
            fclose(file_code);

            free(pass_clear);  
            free(pass_key);
            free(pass_code);
            free(pass_code_saved);
            free(code_key); 

            return 0;
           }

          fseek (file_code, pos_crypt, 0);
          bcrypt_fwrite_int (file_mem, 1, block_crypt, file_code,varinit,mode);
         }
       }

/*
 * Probability Seed function call
 */
      if ( (1 == power) || (4 == power) )
       {
/*
 * Second part of the Decrypt process
 * we "seed" the file
 */
        if (0 == memory)
         {
          if(bcrypt_file_seed_prob(choice, file_clear, file_code, tab_seed, 
                                   length_seed, pass_code, code_key, round,
                                   block_crypt, pos_crypt, pos_crypt_write,
                                   mode, varinit) == 0)
           {
            bclean_string(pass_clear, varinit->NB_CHAR, mode);
            bclean_typeint(pass_code, varinit->NB_INDEX,mode);
            bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
            if (BCRYPTLOG != stderr)
             fclose(BCRYPTLOG);
            if (file_clear != file_code)
             fclose(file_clear);
            fclose(file_code);

            free(pass_clear);  
            free(pass_key);
            free(pass_code);
            free(pass_code_saved);
            free(code_key); 

            return 0;
           }
         }
        else
         {
          if(bcrypt_mem_seed_prob (choice, file_mem, tmp_length_mem, tab_seed,
                                   length_seed, pass_code, code_key, round,
                                   mode, varinit) == 0)
           {
            bclean_string(pass_clear, varinit->NB_CHAR, mode);
            bclean_typeint(pass_code, varinit->NB_INDEX,mode);
            bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
	
            bclean_typeint(file_mem, length_mem,mode);
            free(file_mem);
	
            if (BCRYPTLOG != stderr)
             fclose(BCRYPTLOG);
            if (file_clear != file_code)
             fclose(file_clear);
            fclose(file_code);

            free(pass_clear);  
            free(pass_key);
            free(pass_code);
            free(pass_code_saved);
            free(code_key); 

            return 0;
           }

          fseek (file_code, pos_crypt_write , 0);
          bcrypt_fwrite_int (file_mem, 1, (block_crypt - varinit->NB_CHAR),
                             file_code,varinit,mode);

         }
       }

      if (1 < tmp_nb)
       {
        if (0 == temp_progress_big)
         varinit->PROGRESS = varinit->PROGRESS + temp_progress;
        else
         {
          if (5000 <= temp_progress)
           {
            temp_progress = 0;
            varinit->PROGRESS++;
           }
          else
           temp_progress++;
         }
       }
      else
       varinit->PROGRESS = 100;
     }         

/*
 * If we used a tempory we need to delete it !
 * to do it in a secure way, I first fill it with 0
 */
    if ((0 == memory) && (1 < power) && (1 == prob))
     {
      if ((1 == mode) || (2 == mode))
       {
        fprintf(BCRYPTLOG, "\n    Filling tempory file with '0'.");
        fflush(BCRYPTLOG);
       }

      fseek(file_temp,0,0);
      i = 0;

      while(i++ < length_file)
       putc(0, file_temp);

      fclose(file_temp);

      if (1 <= mode)
       {
        fprintf(BCRYPTLOG, "\n    Deleting tempory file.\n");
        fflush(BCRYPTLOG);
       }
		
      remove(name_temp);
     }

    if (1 == mode)
     {
      if (choice == 0)
       {
        fprintf(BCRYPTLOG,"    Done. \n -> DECRYPT file function Finished.\n");
        fflush(BCRYPTLOG);
       }
     }

    bclean_string(pass_clear, varinit->NB_CHAR, mode);
    bclean_typeint(pass_code, varinit->NB_INDEX,mode);

    if (1 == memory)
     {
      bclean_typeint(file_mem, length_mem,mode);
      free(file_mem);
     }

    varinit->PROGRESS = 100;

    if (BCRYPTLOG != stderr)
     fclose(BCRYPTLOG);

    if (file_clear != file_code)
     fclose(file_clear);
    fclose(file_code);

    free(pass_clear);  
    free(pass_key);
    free(pass_code);
    free(pass_code_saved);
    free(code_key); 

    if (2<=power)
     free(tab_shuffle);

    return 1;

  }

}

/*
 * === STREAM CRYPT ===
 * 
 * Similar to the bfile function but here I am only crypting
 * strings ! so I only use memory functions
 *
 * For more info please look at bfile() !!
 *
 * choice = 0 : crypt
 * choice = 1 : uncrypt
 *
 * power = 0  : Seed only
 * power = 1  : Probility Seed
 * power = 2  : Shuffle only
 * power = 3  : Seed and Shuffle
 * power = 4  : Probility Seed and Shuffle
 *
 * Please note that if you are using the probability seed function
 * If you crypt:
 * The string aray sent in parameter HAS to have "varinit->NB_CHAR" 
 * more characters allocated to it, as we will add the random
 * key to the stream
 *
 * If you decrypt:
 * The last "varinit->NB_CHAR" characters of the string won't have
 * any relevant data, just garbage !
 *
 */
RETURN_TYPE
bstream 
 (int choice, unsigned char *stringtocrypt, int length_string,
  char *name_key, unsigned char *pass_param, int length_pass, int power,
  int round, int block_shuffle, int mode, globalvar *varinit)
{
 int tmp, i, k, l, shift = 0, shiftfix;
 int length_seed, length_stream, length_shuffle, prob;
 int *tab_seed=NULL, *tab_shuffle=NULL;
 int new_shuffle;

 unsigned char *pass_key, *pass_clear;
  
 TYPE_INT *pass_code, *pass_code_saved, *code_key, *stream_mem;

 FILE *file_key;

 prob = 0;
 length_seed =0;
 length_shuffle=0;


 if (1 <= mode)
  {
   if (0 == choice)
    {
     fprintf (BCRYPTLOG, "\n\n -> CRYPT  Stream function started.");
     fprintf (BCRYPTLOG, "\n    POWER          : %d.",power);
     fprintf(BCRYPTLOG, "\n    String's length: %d.",length_string);
    }
   else
    {
     fprintf (BCRYPTLOG, "\n\n -> DECRYPT Stream function started.");
     fprintf (BCRYPTLOG, "\n   POWER          : %d.",power);
     fprintf(BCRYPTLOG,"\n    String's length: %d.",length_string);
    }
    fflush(BCRYPTLOG);
  }

 if ((0 > power) || (4 < power))
  {
   if ((1 == mode) || (2 == mode))
    fprintf (BCRYPTLOG, "\n ERROR.\nPower level '%d' NOT AVAILABLE \n", power);

   bclean_string(pass_param, length_pass, mode);
   fflush(BCRYPTLOG);
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);
   return 0;
  }

 if ((varinit->KEYLENGTH / varinit->NB_BITS) < 2)
  {
   if (1 <= mode)
    {
     fprintf(BCRYPTLOG,"\n ERROR.\nThe KEYLENGTH needs to be at least twice");
     fprintf(BCRYPTLOG," the size of your integer type, in your case >= %d.",
            (varinit->NB_BITS * 2));
     fflush(BCRYPTLOG);
    }
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);
   return 0;
  }

/*
 * We check if we are going to use the probability seed function
 */
 if ((1 == power) || (4 == power))
  prob = 1;

 if (length_string < 1)
  {
   if (1 <= mode)
    fprintf(BCRYPTLOG,"\n ERROR.\nString's length has to be >= 1 \n");

   bclean_string(pass_param, length_pass, mode);
   fflush(BCRYPTLOG);
   if (BCRYPTLOG != stderr) 
    fclose(BCRYPTLOG);
   return 0;
  }

/*
 * If we crypt the string using the probabilit seed function
 * then the string's length will be bigger by KEYLENGTH bits
 */
 if ((0 == choice) && (1 == prob))
  length_string += varinit->NB_CHAR;

 length_stream = length_string / varinit->NB_BYTE;

/*
 * For Algorithmic reasons, the string's length HAS to be 
 * a multiple of the number of bytes the standard INT type 
 * is using
 */
 if ( (length_stream * varinit->NB_BYTE) != length_string)
  length_stream++;

/*
 * Stream_mem is the int array we are going to work on
 */
 stream_mem = (TYPE_INT *) malloc (length_stream * varinit->NB_BYTE);

 if (NULL == stream_mem)
  {
   if (1 <= mode)
    fprintf(BCRYPTLOG, "\n ERROR.\nOUT OF MEMORY! (bstream)\n");

   fflush(BCRYPTLOG);
   if (BCRYPTLOG != stderr) 
    fclose(BCRYPTLOG);
   bclean_string(pass_param, length_pass, mode);
   return 0;
  }

 for (i=0; i< length_stream; i++)
  stream_mem[i] = 0;

 l=0;
 k=0;
 i=0;

 if ((0 == choice) && (1 == prob))
  tmp = length_string - varinit->NB_CHAR;
 else
  tmp = length_string;

/*
 * I need to transfer the character string into the stream_mem 
 * integer aray
 */
 do
  {
   stream_mem[k] |= (TYPE_INT) (stringtocrypt[i] << (8 * l));

   l++;
   if (l == varinit->NB_BYTE)
    {
     l = 0;
     k++;
    }
   i++;
  }
 while (i < tmp);

/*
 * We check the shuffle block
 */
 if (power > 1) 
  {
   if (0 >= block_shuffle)
    block_shuffle = varinit->NB_BYTE;
 
   if (block_shuffle < varinit->NB_BYTE)
    {
     if (1 <= mode)
      {
       fprintf (BCRYPTLOG, "\n ERROR.\nThe block's shuffle has to be at");
       fprintf(BCRYPTLOG," least >= %d \n", varinit->NB_BYTE);
       bclean_string(pass_param, length_pass, mode);
       fflush(BCRYPTLOG);
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);
       return 0;
      }

/*
 * For the "shuffle" function to be useful at least 2/3 of the file
 * has to be mixed together
 *
 * Why 6 ? ;o)
 * if there are 6 blocks to shuffle then we can mix 4 of them
 * it's 4 out of 6 ... 4/6 = 2/3
 * So I check if I will have at least 6 blocks to shuffle
  */
     if ( (length_string / block_shuffle) < 6)
      {
       if (1 <= mode)
        {
         fprintf(BCRYPTLOG,"\n ERROR.\nThe String's length should be at ");
         fprintf(BCRYPTLOG,"least 6 times bigger than the shuffle block.\n");
        }
       bclean_string(pass_param, length_pass, mode);
       fflush(BCRYPTLOG);
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);
       return 0;
      }
 
     if (((block_shuffle/varinit->NB_BYTE)*varinit->NB_BYTE) != block_shuffle)
      {
       if (1 <= mode)
        {
         fprintf(BCRYPTLOG,"\n ERROR.\nThe Shuffle's block has to be a ");
         fprintf(BCRYPTLOG,"multiple of %d.\n", varinit->NB_BYTE);
         fprintf(BCRYPTLOG,"Which is the number of bytes used by this app");
         fprintf(BCRYPTLOG,"for its DEFAULT INTEGER TYPE: TYPE_INT \n");
        }
       bclean_string(pass_param, length_pass, mode);
       fflush(BCRYPTLOG);
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);
       return 0;
      }
    }
  }

 if (varinit->NB_CHAR < length_pass)
  {
   if (1 == mode)
    {
     fprintf(BCRYPTLOG,"\n ERROR.\nWrong password length specified,");
     fprintf(BCRYPTLOG," should not be > %d\n", varinit->NB_CHAR); 
     bclean_string(pass_param, length_pass, mode);
     fflush(BCRYPTLOG);
     if (BCRYPTLOG != stderr) 
      fclose(BCRYPTLOG);
     return 0;
    }
  }
/*
 * We allocate the memory to our local arays
 */
 pass_key = (unsigned char *) malloc (varinit->NB_CHAR);
 pass_clear = (unsigned char *) malloc( varinit->NB_CHAR);
 pass_code = (TYPE_INT *) malloc (varinit->NB_INDEX * varinit->NB_BYTE);
 pass_code_saved=(TYPE_INT *) malloc (varinit->NB_INDEX*varinit->NB_BYTE);
 code_key = (TYPE_INT *) malloc (varinit->NB_INDEX * varinit->NB_BYTE);

 if (NULL == code_key)
  {
   if (1 <= mode)
   fprintf(BCRYPTLOG, "\n ERROR.\nOUT OF MEMORY! (bstream)\n");
   fflush(BCRYPTLOG);

   if (BCRYPTLOG != stderr) 
    fclose(BCRYPTLOG);
   bclean_string(pass_param, length_pass, mode);

   free(stream_mem);
   free(pass_key);
   free(pass_clear);
   free(pass_code);
   free(pass_code_saved);

   return 0;
  }
  
/*
 * I check if the user wants to use a key file
 */
 if ( 0 != strcmp(name_key, ""))
  {
   file_key = fopen (name_key, "rb");
   if (NULL != file_key)
    {
     fseek(file_key, 0, 2);
     length_pass=ftell(file_key);
     if (length_pass < varinit->NB_CHAR)
      {
       if (1 <= mode)
       fprintf(BCRYPTLOG,"\n ERROR.\nKey file length < KEYLENGTH.");
       bclean_string(pass_param, length_pass, mode);
       fflush(BCRYPTLOG);
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);

       free(stream_mem);
       free(pass_key);
       free(pass_clear);
       free(pass_code);
       free(pass_code_saved);
       free(code_key);

       return 0;
      }

     fclose(file_key);
     if (bcrypt_read_keyfile(pass_clear, name_key, mode, varinit) == 0)
      {
       if ((1 == mode) || (2 == mode))
        fprintf(BCRYPTLOG,"\n ERROR.\nRead key file failed.");
       bclean_string(pass_param, length_pass, mode);
       fflush(BCRYPTLOG);
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);

       free(stream_mem);
       free(pass_key);
       free(pass_clear);
       free(pass_code);
       free(pass_code_saved);
       free(code_key);

       return 0;
      }
    }
  }
 else
  {
/*
 * The password's length sent as a parameter has to be
 * at least half of the keylength
 */
   for (i = 0; i < length_pass; i++)
    pass_clear[i] = pass_param[i];
   bclean_string(pass_param, length_pass, mode);

   if (varinit->NB_CHAR < length_pass)
    {
     if ((1 == mode) || (2 == mode))
      {
       fprintf(BCRYPTLOG,"\n ERROR.\nWrong password length specified,");
       fprintf(BCRYPTLOG," should not be > %d\n", varinit->NB_CHAR);
       bclean_string(pass_param, length_pass, mode);
       fflush(BCRYPTLOG);
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);

       free(stream_mem);
       free(pass_key);
       free(pass_clear);
       free(pass_code);
       free(pass_code_saved);
       free(code_key);

       return 0;
      }
    }        
  }

 if ( length_pass < (varinit->NB_CHAR / 2) )
  {
   if (1 <= mode)
    {
     fprintf (BCRYPTLOG, "\n ERROR.\nWrong password length : %d. / %d.",
              length_pass, varinit->NB_CHAR);
     fflush(BCRYPTLOG);
    }

   bclean_string(pass_param, varinit->NB_CHAR, mode);
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);

   free(stream_mem);
   free(pass_key);
   free(pass_clear);
   free(pass_code);
   free(pass_code_saved);
   free(code_key);

   return 0;
  }

/*
 * We set the length of the seed sequence aray
 */
 if (2 != power)
  {
   length_seed = (length_string/varinit->NB_CHAR);
   if ((length_seed * varinit->NB_CHAR) < length_string)
    length_seed++;

   tab_seed = (int *) malloc (length_seed * sizeof(int));
 	
   if (tab_seed == NULL) 
    {
     if ((1 == mode) || (2 == mode))
      {
       fprintf(BCRYPTLOG,"\n ERROR.\nNot Enough memory to allocate for");
       fprintf(BCRYPTLOG," the SEED sequence array.");
       fflush(BCRYPTLOG);
      } 
     bclean_string(pass_param, varinit->NB_CHAR, mode);
     if (BCRYPTLOG != stderr)
      fclose(BCRYPTLOG);

     free(stream_mem);
     free(pass_key);
     free(pass_clear);
     free(pass_code);
     free(pass_code_saved);
     free(code_key);

     return 0;
    }
  }

/*
 * We generate the first key from the password 
 */
 if (bcrypt_test_length (pass_clear, length_pass, mode, varinit) == 0)
  {
   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);

   free(stream_mem);
   free(pass_key);
   free(pass_clear);
   free(pass_code);
   free(pass_code_saved);
   free(code_key);

   return 0;
  }

 length_pass = varinit->NB_CHAR;

 if (bcrypt_transcription (pass_clear, pass_code, mode, varinit) == 0)
  {
   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   bclean_typeint(pass_code, varinit->NB_INDEX,mode);
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);

   free(stream_mem);
   free(pass_key);
   free(pass_clear);
   free(pass_code);
   free(pass_code_saved);
   free(code_key);

   return 0;
  }

 if (bcrypt_add (pass_code, mode, varinit) == 0)
  {
   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   bclean_typeint(pass_code, varinit->NB_INDEX,mode);
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);

   free(stream_mem);
   free(pass_key);
   free(pass_clear);
   free(pass_code);
   free(pass_code_saved);
   free(code_key);

   return 0;
  }

 if (bcrypt_swap (pass_code, round, mode, varinit) == 0)
  {
   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   bclean_typeint(pass_code, varinit->NB_INDEX,mode);
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);

   free(stream_mem);
   free(pass_key);
   free(pass_clear);
   free(pass_code);
   free(pass_code_saved);
   free(code_key);

   return 0;
  }

/*
 * Now that we now the block's crypt we can find how many block's 
 * shuffle there are in a block's crypt
 * We need to initialise tab_shuffle after we generated the first KEY 
 * in case we want to "dynamicaly" change the value of trhe shuffle block.
 */
 if (power > 1)
  {
   if ((varinit->MISC & BMASK_SHUFFLE) == BMASK_SHUFFLE)
    {
     if (2 == mode)
      {
       fprintf(BCRYPTLOG, "\n     Dynamic Shuffle Flag Detected.");
       fflush(BCRYPTLOG);
      }
     i = ((unsigned int)pass_code[1%varinit->NB_INDEX])%varinit->NB_INDEX;

     if (block_shuffle < varinit->NB_BITS)
     new_shuffle = ((unsigned int)pass_code[i])%varinit->NB_BITS;  
     else
      new_shuffle = ((unsigned int)pass_code[i])%block_shuffle;  

     new_shuffle = new_shuffle + block_shuffle;

     new_shuffle = (new_shuffle/varinit->NB_BYTE) * varinit->NB_BYTE;

     while( ((length_string / new_shuffle) < 6) && (new_shuffle > 0))
      new_shuffle = new_shuffle - varinit->NB_BYTE;

     if (new_shuffle < varinit->NB_BYTE)
      {    
       if ((1 == mode) || (2 == mode))
        {
         fprintf(BCRYPTLOG,"\n WARNING.\n Couldn't assign a dynamic value");
         fprintf(BCRYPTLOG," to the block shuffle. \n");
         fflush(BCRYPTLOG);
        }
     }
     else
      {
       if (2 == mode)
        {
         fprintf(BCRYPTLOG,"\n     Old block Shuffle size: %d",block_shuffle);
         fprintf(BCRYPTLOG,"\n     New block SHUFFLE size: %d",new_shuffle);
         fflush(BCRYPTLOG);
        }

       block_shuffle = new_shuffle;
      }
    }

   length_shuffle = (length_string/block_shuffle);
   if ( (length_shuffle * block_shuffle) < length_string ) 
    length_shuffle++;

   tab_shuffle = (int *) malloc (length_shuffle * sizeof(int));

   if (tab_shuffle == NULL) 
    {
     if ((1 == mode) || (2 == mode))
      {
       fprintf(BCRYPTLOG,"\n ERROR.\nNot Enough memory to allocate for");
       fprintf(BCRYPTLOG," the SHUFFLE sequence array.");
       fflush(BCRYPTLOG);
      } 
 
     if (BCRYPTLOG != stderr) fclose(BCRYPTLOG);

     free(stream_mem);
     free(pass_key);
     free(pass_clear);
     free(pass_code);
     free(pass_code_saved);
     free(code_key);

     return 0;
    }
  }

 if (varinit->PROGRESS>=100)
  varinit->PROGRESS = 100;
 else
  varinit->PROGRESS = varinit->PROGRESS + 10;

/*
 * and now we CRYPT !
 */
 if (0 == choice)
  {
   if (1 <= mode)
    {
     fprintf(BCRYPTLOG, "\n\n => Crypting Stream in progress...");
     fprintf (BCRYPTLOG, "\n    String Length                        : %d.",
              length_string);
     fprintf (BCRYPTLOG, "\n    Nb of SEED filter                    : %d.",
              length_seed);
     fprintf (BCRYPTLOG, "\n    Block Shuffle (BS)                   : %d.",
              block_shuffle);
     fprintf (BCRYPTLOG, "\n    Nb of BS filter                      : %d.",
              length_shuffle);
     fprintf (BCRYPTLOG, "\n    Please Wait... \n");
     fflush(BCRYPTLOG);
    }

/*
 * The pass_code will change in bcrypt_file_seed.
 * I need to save the current pass_code value as I will use it in 
 * bcrypt_shuffle
 * And when I decrypt a file I start to unshuffle, so it's quicker if I save
 * the first pass_code value and use it as well with bcrypt_shuffle.
 * Otherwise, when I decrypt a file I would have to generate all the pass_code
 * generated in file_seed first !
 * The file_seed function used anyway the next value of pass_code first.
 */
   memcpy(pass_code_saved, pass_code, varinit->NB_CHAR);

/*
 * Seed function call
 */
   if ( (0 == power) || (3 == power) )
    {

/*
 * First part of the crypt process
 * we "seed" the file
 */
     if(bcrypt_mem_seed (stream_mem, length_stream, tab_seed,length_seed,
                         pass_code, round, mode, varinit) == 0)
      {
       bclean_string(pass_clear, varinit->NB_CHAR, mode);
       bclean_typeint(pass_code, varinit->NB_INDEX,mode);
       bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
       bclean_typeint(stream_mem, length_stream,mode);
	
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);

      free(stream_mem);
      free(pass_key);
      free(pass_clear);
      free(pass_code);
      free(pass_code_saved);
      free(code_key);

       return 0;
      }
    }
	 
/*
 * Probability Seed function call
 */
   if ( (1 == power) || (4 == power) )
    {

/*
 * First part of the crypt process
 * we "seed" the file
 *
 * We translate the long integer from pass_code into some characters
 * in the string pass_clear
 */
     i=0;
     l=0;
     k=0;
 
     shiftfix=varinit->NB_BITS - 8;

     do
      {
       if (l == 0)
        shift = shiftfix;
       else
        shift = shift - 8;

       pass_key[i] = (int)((pass_code[k] << shift) >> shiftfix);

       l++;
       if (l == varinit->NB_BYTE)
        {
         l = 0;
         k++;
        }
       i++;
      }
     while (k < varinit->NB_INDEX);

     if(bpass (code_key, pass_key, length_pass, 0, round, mode, varinit) == 0)
      {
       bclean_string(pass_clear, varinit->NB_CHAR, mode);
       bclean_string(pass_key, varinit->NB_CHAR, mode);
       bclean_typeint(pass_code, varinit->NB_INDEX,mode);

/*
 * I do not close BCRYPTLOG because It has been already done
 * in bpass function.
 */
  
       free(stream_mem);
       free(pass_key);
       free(pass_clear);
       free(pass_code);
       free(pass_code_saved);
       free(code_key);

       return 0;
      }

     if(bcrypt_mem_seed_prob (choice, stream_mem, length_stream, tab_seed,
                              length_seed, pass_code, code_key, round, mode,
                              varinit) == 0)
      {
       bclean_string(pass_clear, varinit->NB_CHAR, mode);
       bclean_typeint(pass_code, varinit->NB_INDEX,mode);
       bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
       bclean_typeint(stream_mem, length_stream,mode);
	
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);

       free(stream_mem);
       free(pass_key);
       free(pass_clear);
       free(pass_code);
       free(pass_code_saved);
       free(code_key);

       return 0;
      }
  
    }

   varinit->PROGRESS = varinit->PROGRESS + 40;

/*
 * Shuffle function call
 */
   if (1 < power)
    {
/*
 * Second part of the crypt process
 * We shuffle the blocks of the file
 */
     if(bcrypt_mem_shuffle (stream_mem, length_stream, tab_shuffle,
                            length_shuffle, pass_code_saved, round,
                            block_shuffle, mode, varinit) == 0)
      {
       bclean_string(pass_clear, varinit->NB_CHAR, mode);
       bclean_typeint(pass_code, varinit->NB_INDEX,mode);
       bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
       bclean_typeint(stream_mem, length_stream,mode);

       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);

       free(stream_mem);
       free(pass_key);
       free(pass_clear);
       free(pass_code);
       free(pass_code_saved);
       free(code_key);

       return 0;
      }
    }	

   varinit->PROGRESS = varinit->PROGRESS + 40;

/*
 * We translate the long integer from pass_code into some characters
 * in the string pass_clear
 */
   l=0;
   k=0;
   i=0;
   shiftfix=varinit->NB_BITS - 8;

/*
 * We save the result in the original string sent in the parameters
 */	
   do
    {
     if (l == 0) 
      shift = shiftfix;
     else
      shift = shift - 8;
	
     stringtocrypt[i] = (int)((stream_mem[k] << shift) >> shiftfix);
     l++;
     if (l == varinit->NB_BYTE)
      {
       l = 0;
       k++;
      }
     i++;
    }
   while (i < length_string);

   if (1 <= mode)
    {    
     if (choice == 0)
      {
       fprintf(BCRYPTLOG, " Done. \n -> CRYPT Stream function Finished.\n");
       fflush(BCRYPTLOG);
      }
    }

   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   bclean_typeint(pass_code, varinit->NB_INDEX,mode);
   bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
   bclean_typeint(stream_mem, length_stream,mode);

   free(stream_mem);
   free(pass_key);
   free(pass_clear);
   free(pass_code);
   free(pass_code_saved);
   free(code_key);

   varinit->PROGRESS = 100;

   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);

   return 1;

  }
 else
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG, "\n\n => DEcrypting Stream in progress...");
     fprintf(BCRYPTLOG, "\n    String Length                      : %d.",
             length_string);
     fprintf(BCRYPTLOG, "\n    Nb of SEED filter                  : %d.",
             length_seed);
     fprintf(BCRYPTLOG, "\n    Block Shuffle (BS)                 : %d.",
             block_shuffle);
     fprintf(BCRYPTLOG, "\n    Nb of BS filter                    : %d.",
             length_shuffle);
    fprintf(BCRYPTLOG, "\n    Please wait... \n");
     fflush(BCRYPTLOG);
    }
 	
   for (i=0; i < varinit->NB_INDEX; i++) pass_code_saved[i] = pass_code[i];

/*
 * Unshuffle function call
 */
   if (1 < power)
    {
     if(bcrypt_mem_unshuffle (stream_mem, length_stream, tab_shuffle,
                              length_shuffle, pass_code_saved, round,
                              block_shuffle, mode, varinit) == 0)
      {
       bclean_string(pass_clear, varinit->NB_CHAR, mode);
       bclean_typeint(pass_code, varinit->NB_INDEX,mode);
       bclean_typeint(stream_mem, length_stream,mode);
  	
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);

       free(stream_mem);
       free(pass_key);
       free(pass_clear);
       free(pass_code);
       free(pass_code_saved);
       free(code_key);

       return 0;
      }
    }

   varinit->PROGRESS = varinit->PROGRESS + 40;

/*
 * Seed function call
 */
   if ( (0 == power) || (3 == power) )
    {
/*
 * Second part of the DEcrypt process
 * we "seed" the file
 */
     if(bcrypt_mem_seed (stream_mem, length_stream, tab_seed,length_seed,
                         pass_code, round, mode, varinit) == 0)
      {
       bclean_string(pass_clear, varinit->NB_CHAR, mode);
       bclean_typeint(pass_code, varinit->NB_INDEX,mode);
       bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
       bclean_typeint(stream_mem, length_stream,mode);
	
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);

       free(stream_mem);
       free(pass_key);
       free(pass_clear);
       free(pass_code);
       free(pass_code_saved);
       free(code_key);

       return 0;
      }
    }

/*
 * Probability Seed function call
 */
   if ( (1 == power) || (4 == power) )
    {
/*
 * Second part of the Decrypt process
 * we "seed" the file
 */
     if(bcrypt_mem_seed_prob (choice, stream_mem, length_stream, tab_seed,
                              length_seed, pass_code, code_key, round, mode,
                              varinit) == 0)
      {
       bclean_string(pass_clear, varinit->NB_CHAR, mode);
       bclean_typeint(pass_code, varinit->NB_INDEX,mode);
       bclean_typeint(pass_code_saved, varinit->NB_INDEX,mode);
       bclean_typeint(stream_mem, length_stream,mode);
	
       if (BCRYPTLOG != stderr)
        fclose(BCRYPTLOG);

       free(stream_mem);
       free(pass_key);
       free(pass_clear);
       free(pass_code);
       free(pass_code_saved);
       free(code_key);

       return 0;
      }
    }         

/*
 * We translate the long integer from pass_code into some characters
 * in the string pass_clear
 */
   l=0;
   k=0;
   i=0;
   shiftfix=varinit->NB_BITS - 8;
   tmp = length_string - (prob * varinit->NB_CHAR);

/*
 * We save the result in the original string sent in the parameters
 */	
   do
    {
     if (l == 0)
      shift = shiftfix;
     else
      shift = shift - 8;

     stringtocrypt[i] = (int)((stream_mem[k] << shift) >> shiftfix);
     l++;
     if (l == varinit->NB_BYTE)
      {
       l = 0;
       k++;
      }
     i++;
    }
   while (i < tmp);

   varinit->PROGRESS = varinit->PROGRESS + 40;

   if ((1 == mode) || (2 == mode))
    {
     if (choice == 0)
      {
       fprintf(BCRYPTLOG, " Done. \n -> DECRYPT Stream function Finished.\n");
       fflush(BCRYPTLOG);
      }
    }

   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   bclean_typeint(pass_code, varinit->NB_INDEX,mode);
   if (BCRYPTLOG != stderr)
    fclose(BCRYPTLOG);

   varinit->PROGRESS = 100;

   bclean_typeint(stream_mem, length_stream,mode);

   free(stream_mem);
   free(pass_key);
   free(pass_clear);
   free(pass_code);
   free(pass_code_saved);
   free(code_key);

   return 1;
  }
}
