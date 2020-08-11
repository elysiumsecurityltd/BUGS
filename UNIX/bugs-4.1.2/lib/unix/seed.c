/*
 * seed.c
 *
 * SEED FUNCTIONS
 *
 *  B U G S - LIBRARY
 *
 *  DYNAMIC CRYPTOGRAPHY ALGORITHM
 *  Version 4.1.0  - "IBIZA"
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
 * These are my own headers
 */
#define _BUGSCRYPT_SEED

#include "../../include/seed.h"
#include "../../include/main.h"
#include "../../include/utils.h"   

/* 
 * === SEED FILE FUNCTION ===
 *
 * Crypt a file X in a file Y
 *
 * I define an aray A of n integer,
 * where n * varinit->NB_INDEX * varinit->NB_BYTE = X file's length
 * (The truth is not out there, but in this algorithm ... ;o)
 * Then I will be able to add a filter that is a cipher text of
 * varinit->NB_INDEX*varinit->NB_BYTE
 * bytes in the X file, the position of this filter is function of the 
 * passwd typed by the user.
 * I change the aray A to be sure to do not add a filter at the same 
 * position again.
 * When all the aray A has been filled, that means that all the X file has
 * been crypted.
 * 
 * IMPORTANT NOTE:
 * the first filter is the cypher text C1 of the passwd typed by the user,
 * AND THE SECOND FILTER is the cypher text of C1.
 * Indeed, I use C1 like a new passwd, and to crypt another part of my 
 * X file I will use C2 to generate C3, etc ... 
 */
int
bcrypt_file_seed
 (FILE *file_clear, FILE *file_code, int *tab_seed, int length_seed,
  TYPE_INT *pass_code, int round, int block_crypt, int pos_crypt,
  int mode, globalvar *varinit)
{

 int i, j, pos, nb_code, temp_progress = 0;
 int rest_byte, tmp_rest_byte, shiftfix;
 unsigned char *pass_clear;
 TYPE_INT *file_tempvar;

 int l,k,shift = 0;
 int new_buffer, indexa, indexb, index_temp;
 TYPE_INT **pass_buffer, *pass_buffer_keys;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Seed FILE function Started.");
   fflush(BCRYPTLOG);
  }

 new_buffer = 1;

 if (1 < varinit->KEY_BUFFER)
  {
   new_buffer = varinit->KEY_BUFFER;
   if ((varinit->MISC & BMASK_BUFFER) == BMASK_BUFFER)
    {
     i = ((unsigned int)pass_code[0])%varinit->NB_INDEX;

     new_buffer += ((unsigned int)pass_code[i])%varinit->KEY_BUFFER;    

     if (2 == mode)
      {
       fprintf(BCRYPTLOG, "\n     Dynamic Buffer Flag Detected.");
       fprintf(BCRYPTLOG, "\n     Old Key buffer size: '%d'",
               varinit->KEY_BUFFER);
       fprintf(BCRYPTLOG, "\n     New Key buffer size: '%d'",new_buffer);
       fflush(BCRYPTLOG);
      }
    }
  }

 pass_buffer= (TYPE_INT **) malloc(new_buffer * sizeof(TYPE_INT *)); 
 pass_buffer_keys= (TYPE_INT *)malloc(new_buffer*varinit->NB_CHAR); 
 pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);
 file_tempvar = (TYPE_INT *) malloc (varinit->NB_CHAR);

 if ((NULL == pass_buffer) || (NULL == pass_buffer_keys) ||
     (NULL == pass_clear) || (NULL == file_tempvar))
  {
   if(mode>= 1)
    fprintf(BCRYPTLOG, "\n ERROR.\nOUT OF MEMORY! (bcrypt_file_seed)\n");

   free(pass_buffer);
   free(pass_buffer_keys);
   free(pass_clear);
   free(file_tempvar);

   return 0;
  }
 
 for(i=0; i<new_buffer; i++)
  pass_buffer[i]= pass_buffer_keys+(i*varinit->NB_INDEX);
 
 for (i=0; i<length_seed; i++)
  tab_seed[i] = 0;  

/*
 * I do not start with the first pass_code generated
 * This is because I may also use it with bcrypt_file_shuffle
 *
 * We translate the long integer from pass_code into some characters
 * in the string pass_clear
 */
 l=0;
 k=0;
 i=0;
 shiftfix = (varinit->NB_BITS) - 8;
 do
  {
   if (l == 0)
    shift = shiftfix;
   else
    shift = shift - 8; 

   pass_clear[i] = (int)((pass_code[k] << shift) >> shiftfix);
     
   l++;
   if (l == varinit->NB_BYTE) 
    {
     l = 0;
     k++;
    }
   i++;
  }
 while (k < varinit->NB_INDEX);

 if (bcrypt_transcription (pass_clear, pass_code, mode, varinit) == 0)
  return 0;

 if (bcrypt_add (pass_code, mode, varinit) == 0)
  return 0;

 if (bcrypt_swap (pass_code, round, mode, varinit) == 0)
  return 0;

/*
 * We generate 16 keys (if default value) that will be used as a buffer
 * to generate the key we will use. 
 * Thanks to that we create a dependancy on ALL the previous key and not
 * only on the first key.
 */
 memcpy(pass_buffer[0], pass_code, varinit->NB_CHAR);
 
 shiftfix = (varinit->NB_BITS) - 8; 
 
 for (j = 1; j<new_buffer; j++)
  {
   l=0;
   k=0;
   i=0;
   do
    {
     if (l == 0) shift = shiftfix;
      else
     shift = shift - 8; 

     pass_clear[i] = (int)((pass_buffer[j-1][k] << shift) >> shiftfix);
     
     l++;
     if (l == varinit->NB_BYTE) 
      {
       l = 0;
       k++;
      }
     i++;
    }
   while (k < varinit->NB_INDEX);

   if (bcrypt_transcription (pass_clear, pass_buffer[j], mode, varinit) == 0)
    return 0;

   if (bcrypt_add (pass_buffer[j], mode, varinit) == 0)
    return 0;

   if  (bcrypt_swap (pass_buffer[j], round, mode, varinit) == 0)
    return 0;

  }

 if (1 < new_buffer)
  { 
   i = pass_code[0]%varinit->NB_INDEX;
   indexa = pass_code[i]%new_buffer;

   i = pass_code[1%varinit->NB_INDEX]%varinit->NB_INDEX;
   indexb = pass_code[i]%new_buffer;

   if (indexa == indexb) indexb = (indexb + 1)%new_buffer;

/*
 * indexb will start with the last bit rather than the first bit.
 * this is in the unlikely event that indexa = indexb
 * It could happened if new_buffer=1
 */
    for (i=0; i<varinit->NB_INDEX; i++)
     {
      pass_code[i] = pass_buffer[indexa][i]&
                     pass_buffer[indexb][(varinit->NB_INDEX - 1 - i)];
     }
   }
  else
   {
     indexa = 0;
     indexb = 0;
     memcpy(pass_code, pass_buffer[indexa], varinit->NB_CHAR);
   }

 j=0;
 nb_code=0;
  

 do
  {
/*
 *  We find where we are going to insert the filter 
 */
   pos = pass_code[j]%length_seed;
   j = (j + 1)%varinit->NB_INDEX;

   while (tab_seed[pos] == 1)
    pos = (pos + 1) % length_seed;

   tab_seed[pos] = 1;
   pos *= varinit->NB_CHAR;

   if ( (pos + varinit->NB_CHAR) <= block_crypt)
    {

/*
 * we go to the position 'pos' in the file to crypt
 */
     fseek (file_clear, (pos_crypt + pos), 0);
	
/*
 * We save the file data to crypt in file_tempvar
 * We read (varinit->NB_BYTE * varinit->NB_INDEX) bytes from the clear
 * file
 */
     bcrypt_fread_int (file_tempvar, varinit->NB_BYTE, varinit->NB_INDEX,
                       file_clear, varinit, mode);
	
/*
 * We go the the same position in the file that will
 * receive the crypted data
 */	
     fseek (file_code, (pos_crypt + pos), 0);

     for (i = 0; i < varinit->NB_INDEX; i++)
      file_tempvar[i] ^= pass_code[i];

     bcrypt_fwrite_int (file_tempvar, varinit->NB_BYTE,
                        varinit->NB_INDEX, file_code,varinit,mode);
	
    } 
   else
    {
     rest_byte = (block_crypt - pos);
 
 	 if (2 == mode)
      {
       fprintf(BCRYPTLOG,
 		      "\n    End of File's number of bytes to crypt : %d.",
               rest_byte);
       fflush(BCRYPTLOG);
 	  }

/*
 * we go to the position 'pos' in the file to crypt
 */
     fseek (file_clear, (pos_crypt + pos), 0);
 
/*
 * We save the file data to crypt in file_tempvar
 * We read '1 * rest_byte' bytes from the clear file
 */
     bcrypt_fread_int (file_tempvar, rest_byte, 1, file_clear,varinit,mode);
	
/*
 * We go the the same position in the file that will
 * receive the crypted data
 */
     fseek (file_code, (pos_crypt + pos), 0);
	
     i = 0;
     tmp_rest_byte = rest_byte;

     do
      {
       file_tempvar[i] ^= pass_code[i%varinit->NB_INDEX];
       tmp_rest_byte-= varinit->NB_BYTE;
       i++;
      }
     while ( tmp_rest_byte > 0 );
	
     bcrypt_fwrite_int(file_tempvar, 1, rest_byte, file_code,varinit,mode);
    }

   nb_code++;

/*
 * The cipher text becomes the new 'typed' passwd
 * 
 * this function seems to have problems to put some long integer
 * in a string ...
 * strncpy(pass_clear,pass_code,varinit->NB_CHAR);
 * that is why I have done the following function.
 *
 * We translate the long integer from pass_code into some characters
 * in the string pass_clear
 */
   l=0;
   k=0;
   i=0;

   do
    {
     if (l == 0)
      shift = shiftfix;
     else
      shift = shift - 8; 
 
     pass_clear[i] = (int)((pass_code[k] << shift) >> shiftfix);
       
     l++;
     if (l == varinit->NB_BYTE) 
      {
       l = 0;
       k++;
      }
     i++;
    }
   while (k < varinit->NB_INDEX);


   if
    (bcrypt_transcription (pass_clear, pass_buffer[indexa], mode, varinit) == 0)
     return 0;

   if (bcrypt_add (pass_buffer[indexa], mode, varinit) == 0)
    return 0;

   if (bcrypt_swap (pass_buffer[indexa], round, mode, varinit) == 0)
    return 0;
  
   if (1 < new_buffer)
    {
     index_temp=indexa;

     i = pass_buffer[indexb][0]%varinit->NB_INDEX;
     indexa = pass_buffer[indexb][i]%new_buffer;
     i = pass_buffer[indexb][1%varinit->NB_INDEX]%varinit->NB_INDEX;
     indexb = pass_buffer[indexb][i]%new_buffer;

/*
 * We don't want to use the last key used to crypt
 */
     if (indexa == index_temp) indexa = (indexa + 1)%new_buffer;
     if (indexb == index_temp) indexb = (indexb + 1)%new_buffer;

  
     if (indexa == indexb) indexb = (indexb + 1)%new_buffer;

  /*
   * indexb will start with the last bit rather than the first bit.
   * this is in the unlikely event that indexa = indexb
   * It could happened if varinit->NB_INDEX = 1
   */
     for (i=0; i<varinit->NB_INDEX; i++)
      {
       pass_code[i] = pass_buffer[indexa][i]&
                      pass_buffer[indexb][(varinit->NB_INDEX - 1 - i)];
      }
    }
   else
    memcpy(pass_code, pass_buffer[indexa], varinit->NB_CHAR);
                                  
   if (varinit->PROGRESS < 50)
    {
     if (5000 <= temp_progress)
      {
       temp_progress = 1;
       varinit->PROGRESS++;
      }
     else 
      temp_progress++;
    }

  }
 while ((nb_code < length_seed) && (varinit->MISC != 1));

 bclean_string(pass_clear, varinit->NB_CHAR, mode);

 free(pass_buffer);
 free(pass_buffer_keys);
 free(pass_clear);
 free(file_tempvar);

 if (varinit->MISC == 1)
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG,"\n WARNING: BREAK SIGNAL DETECTED. STOPPING...");
     fflush(BCRYPTLOG);
    }
   return 0;
  }

 if (2 == mode)
  {
   fprintf(BCRYPTLOG,"\n -> Seed FILE function Finished.");
   fflush(BCRYPTLOG);
  }

 return 1;

}

/*
 * 
 * === SEED MEM FUNCTION ===
 *
 * This function is similar to the file_seed one.
 * The only difference here is that I am working with the data
 * held in memory in an array called file_mem.
 *
 */
int
bcrypt_mem_seed 
 (TYPE_INT *file_mem, int length_mem, int *tab_seed, int length_seed,
  TYPE_INT *pass_code, int round, int mode, globalvar *varinit)
{

 int i, j, pos, nb_code, temp_progress = 0;
 int shiftfix;
 unsigned char *pass_clear;

 int l,k,shift = 0;
 int new_buffer, indexa, indexb, index_temp;

 TYPE_INT **pass_buffer, *pass_buffer_keys;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Seed MEM function Started.");
   fflush(BCRYPTLOG);
  }

 new_buffer=1;

 if (1 < varinit->KEY_BUFFER)
  { 
   new_buffer = varinit->KEY_BUFFER;
   if ((varinit->MISC & BMASK_BUFFER) == BMASK_BUFFER)
    {
     i = ((unsigned int)pass_code[0])%varinit->NB_INDEX;

     new_buffer+= ((unsigned int)pass_code[i])%varinit->KEY_BUFFER;    

     if (2 == mode)
      {
       fprintf(BCRYPTLOG, "\n     Dynamic Buffer Flag Detected.");
       fprintf(BCRYPTLOG, "\n     Old Key buffer size: '%d'",
               varinit->KEY_BUFFER);
       fprintf(BCRYPTLOG, "\n     New Key buffer size: '%d'",new_buffer);
       fflush(BCRYPTLOG);
      }
    }
  }

 pass_buffer= (TYPE_INT **)malloc(new_buffer*sizeof(TYPE_INT *));
 pass_buffer_keys= (TYPE_INT *)malloc(new_buffer*varinit->NB_CHAR); 
 pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);

 if ((NULL == pass_buffer) || (NULL == pass_buffer_keys) ||
     (NULL == pass_clear)) 
  {
   if(mode>= 1)
    fprintf(BCRYPTLOG, "\n ERROR.\nOUT OF MEMORY! (bcrypt_mem_seed)\n");

   free(pass_buffer);
   free(pass_buffer_keys);
   free(pass_clear);

   return 0;
  }


 for(i= 0; i< new_buffer; i++)
  pass_buffer[i]= pass_buffer_keys + (i*varinit->NB_INDEX); 

 for (i=0; i<length_seed; i++)
  tab_seed[i] = 0;  

/*
 * I do not start with the first pass_code generated
 * This is because I may also use it with bcrypt_file_shuffle
 *
 * We translate the long integer from pass_code into some characters
 * in the string pass_clear
 */
 l=0;
 k=0;
 i=0;
 shiftfix = (varinit->NB_BITS) - 8;
 do
  {
   if (l == 0)
    shift = shiftfix;
   else
    shift = shift - 8; 

   pass_clear[i] = (int)((pass_code[k] << shift) >> shiftfix);
     
   l++;
   if (l == varinit->NB_BYTE) 
    {
     l = 0;
     k++;
    }
   i++;
  }
 while (k < varinit->NB_INDEX);

 if (bcrypt_transcription (pass_clear, pass_code, mode, varinit) == 0)
  return 0;

 if (bcrypt_add (pass_code, mode, varinit) == 0)
  return 0;

 if (bcrypt_swap (pass_code, round, mode, varinit) == 0)
  return 0;

/*
 * We generate 32 keys that will be used as a buffer to generate
 * the key we will use. 
 * Thanks to that we create a dependancy on ALL the previous key and not
 * only on the first key.
 */
 memcpy(pass_buffer[0], pass_code, varinit->NB_CHAR);
 
 shiftfix = (varinit->NB_BITS) - 8; 

 for (j = 1; j<new_buffer; j++)
  {
   l=0;
   k=0;
   i=0;
   do
    {
     if (l == 0) shift = shiftfix;
      else
     shift = shift - 8; 

     pass_clear[i] = (int)((pass_buffer[j-1][k] << shift) >> shiftfix);
     
     l++;
     if (l == varinit->NB_BYTE) 
      {
       l = 0;
       k++;
      }
     i++;
    }
   while (k < varinit->NB_INDEX);

   if (bcrypt_transcription (pass_clear, pass_buffer[j], mode, varinit) == 0)
    return 0;

   if (bcrypt_add (pass_buffer[j], mode, varinit) == 0)
    return 0;

   if (bcrypt_swap (pass_buffer[j], round, mode, varinit) == 0)
    return 0;
  }
 if (1 < new_buffer)
  {  
   i = pass_code[0]%varinit->NB_INDEX;
   indexa = pass_code[i]%new_buffer;

   i = pass_code[1%varinit->NB_INDEX]%varinit->NB_INDEX;
   indexb = pass_code[i]%new_buffer;

   if (indexa == indexb) indexb = (indexb + 1)%new_buffer;
 
/*
 * indexb will start with the last bit rather than the first bit.
 * this is in the unlikely event that indexa = indexb
 * It could happened if varinit->NB_INDEX = 1
 */
   for (i=0; i<varinit->NB_INDEX; i++)
    {
     pass_code[i] = pass_buffer[indexa][i]&
                    pass_buffer[indexb][(varinit->NB_INDEX - 1 - i)];
    }
  }
 else
  {
   indexa = 0;
   indexb = 0;
   memcpy(pass_code, pass_buffer[indexa], varinit->NB_CHAR);
  }  
     
 j=0; 
 nb_code=0;

 do
  {
/*
 *  We find where we are going to insert the filter 
 */
   pos = pass_code[j]%length_seed;
   j = (j + 1)%varinit->NB_INDEX;

   while (tab_seed[pos] == 1)
    pos = (pos + 1) % length_seed;

   tab_seed[pos] = 1;
	
   pos = (pos * varinit->NB_INDEX);
	
   for (i = 0; i < varinit->NB_INDEX; i++)
    {
     if (pos < length_mem)
      {
       file_mem[pos] ^= pass_code[i];
       pos++;
      }
    }

   nb_code++;

/*
 * The cipher text becomes the new 'typed' passwd
 *
 * this function seems to have problems to put some long integer
 * in a string ...
 * strncpy(pass_clear,pass_code,varinit->NB_CHAR);
 * that is why I have done the following function.
 *
 * We translate the long integer from pass_code into some characters
 * in the string pass_clear
 */
   l=0;
   k=0;
   i=0;

   do
    {
     if (l == 0) shift = shiftfix;
      else
     shift = shift - 8; 

     pass_clear[i] = (int)((pass_code[k] << shift) >> shiftfix);
       
     l++;
     if (l == varinit->NB_BYTE) 
      {
       l = 0;
       k++;
      }
     i++;
     
    }
   while (k < varinit->NB_INDEX);


   if
    (bcrypt_transcription (pass_clear, pass_buffer[indexa], mode, varinit) == 0)
     return 0;

   if (bcrypt_add (pass_buffer[indexa], mode, varinit) == 0)
    return 0;

   if (bcrypt_swap (pass_buffer[indexa], round, mode, varinit) == 0)
    return 0;

   if (1 < new_buffer)
    {
     index_temp=indexa;

     i = pass_buffer[indexb][0]%varinit->NB_INDEX;
     indexa = pass_buffer[indexb][i]%new_buffer;

     i = pass_buffer[indexb][1%varinit->NB_INDEX]%varinit->NB_INDEX;
     indexb = pass_buffer[indexb][i]%new_buffer;

/* 
 * We don't want to use the last key used to crypt
 */
     if (indexa == index_temp) indexa = (indexa + 1)%new_buffer;
     if (indexb == index_temp) indexb = (indexb + 1)%new_buffer;

     if (indexa == indexb) indexb = (indexb + 1)%new_buffer;
  
/*
 * indexb will start with the last bit rather than the first bit.
 * this is in the unlikely event that indexa = indexb
 * It could happened if new_buffer = 1
 */
     for (i=0; i<varinit->NB_INDEX; i++)
      {
       pass_code[i] = pass_buffer[indexa][i]&
                      pass_buffer[indexb][(varinit->NB_INDEX - 1 - i)];
      }
    }
   else
     memcpy(pass_code, pass_buffer[indexa], varinit->NB_CHAR);

   if (varinit->PROGRESS < 50)
    {
     if (5000 <= temp_progress)
      {
       temp_progress = 1;
       varinit->PROGRESS++;
      }
     else 
      temp_progress++;
    }
  }
 while ((nb_code < length_seed) && (varinit->MISC != 1));

 bclean_string(pass_clear, varinit->NB_CHAR, mode);

 free(pass_buffer);
 free(pass_buffer_keys);
 free(pass_clear);

 if (varinit->MISC == 1)
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG,"\n WARNING: BREAK SIGNAL DETECTED. STOPPING...");
     fflush(BCRYPTLOG);
    }
   return 0;
  }

 if (2 == mode)
  {
   fprintf(BCRYPTLOG,"\n -> Seed MEM function Finished.");
   fflush(BCRYPTLOG);
  }

 return 1;

}


/*
 * 
 * === PROBABILITY SEED FILE ===
 *
 * This function is quite similar to the seed_file one.
 *
 * The difference is that I use a random number to generate my filter.
 * I generate ONE random number, I crypt it and save it in a pseudo
 * random place in the file, and I use this random number in the passwd
 * generation.
 *
 * Like that for ONE passwd and ONE clear text I have MANY cipher text
 *
 * To do that I had to add in the crypted file some data, the length
 * of them is equal to the key length used.
 * 
 * If someone try to uncrypt a cipher file, he will never be
 * sure that he found the good clear file.
 */
int
bcrypt_file_seed_prob 
 (int choice, FILE *file_clear, FILE *file_code, int *tab_seed,
  int length_seed, TYPE_INT *pass_code, TYPE_INT *code_key, 
  int round, int block_crypt, int pos_crypt,
  int pos_crypt_write, int mode, globalvar *varinit)
{

 int i, j, pos, pos_read, pos_write, poskey, nb_code, temp_progress = 0;
 int rest_byte, tmp_rest_byte, shiftfix;
 unsigned char *pass_clear;
 TYPE_INT *file_tempvar, random_key;

 int l,k,shift = 0;

 int new_buffer, indexa, indexb, index_temp;

 TYPE_INT **pass_buffer, *pass_buffer_keys;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> PROB Seed FILE function Started.");
   fflush(BCRYPTLOG);
  }

 new_buffer = 1;
 
 if (1 < varinit->KEY_BUFFER)
  {
   new_buffer = varinit->KEY_BUFFER;
   if ((varinit->MISC & BMASK_BUFFER) == BMASK_BUFFER)
    {
     i = ((unsigned int)pass_code[0])%varinit->NB_INDEX;

     new_buffer += ((unsigned int)pass_code[i])%varinit->KEY_BUFFER;    

     if (2 == mode)
      {
       fprintf(BCRYPTLOG, "\n     Dynamic Buffer Flag Detected.");
       fprintf(BCRYPTLOG, "\n     Old Key buffer size: '%d'",
               varinit->KEY_BUFFER);
       fprintf(BCRYPTLOG, "\n     New Key buffer size: '%d'",new_buffer);
       fflush(BCRYPTLOG);
      }
    }
  }

 pass_buffer= (TYPE_INT **) malloc(new_buffer * sizeof(TYPE_INT *));
 pass_buffer_keys= (TYPE_INT *)malloc(new_buffer*varinit->NB_CHAR);    
 pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);
 file_tempvar = (TYPE_INT *) malloc ((varinit->NB_INDEX * varinit->NB_BYTE));

 if ((NULL == pass_buffer) || (NULL == pass_buffer_keys) ||
     (NULL == pass_clear) || (NULL == file_tempvar)) 
  {
   if(mode>= 1)
    fprintf(BCRYPTLOG, "\n ERROR.\nOUT OF MEMORY! (bcrypt_file_prob_seed)\n");

   free(pass_buffer);
   free(pass_buffer_keys);
   free(pass_clear);
   free(file_tempvar);

   return 0;
  }


 nb_code = 0;

 for(i=0; i<new_buffer; i++)
  pass_buffer[i]= pass_buffer_keys+(i*varinit->NB_INDEX); 

 for (i=0; i<length_seed; i++)
  tab_seed[i] = 0;  

/*
 * I do not start with the first pass_code generated
 * This is because I may also use it with bcrypt_file_shuffle
 *
 * We translate the long integer from pass_code into some characters
 * in the string pass_clear
 */
 l=0;
 k=0;
 i=0;
 shiftfix = (varinit->NB_BITS) - 8;
 do
  {
   if (l == 0)
    shift = shiftfix;
   else
    shift = shift - 8; 

   pass_clear[i] = (int)((pass_code[k] << shift) >> shiftfix);
     
   l++;
   if (l == varinit->NB_BYTE) 
    {
     l = 0;
     k++;
    }
   i++;
  }
 while (k < varinit->NB_INDEX);

 if (bcrypt_transcription (pass_clear, pass_code, mode, varinit) == 0)
  return 0;

 if (bcrypt_add (pass_code, mode, varinit) == 0)
  return 0;

 if (bcrypt_swap (pass_code, round, mode, varinit) == 0)
  return 0;

/*
 *  We find where we are going to insert the Random key
 */
 poskey = pass_code[0]%(length_seed - 1);
 poskey = poskey * varinit->NB_CHAR;

/*
 * we go to the position 'pos' in the file to crypt
 */
 fseek (file_clear, (pos_crypt + poskey), 0);

/*
 * We go the the same position in the file that will
 * receive the crypted data
 */
 fseek (file_code, (pos_crypt_write + poskey), 0);

 if (choice == 0)
  {
   for (i = 0; i < varinit->NB_INDEX; i++)
    file_tempvar[i] = (pass_code[i] ^ code_key[i]);

   bcrypt_fwrite_int (file_tempvar, varinit->NB_BYTE, varinit->NB_INDEX,
                      file_code,varinit,mode);
  }
 else
  {
/*
 * We save the file data to crypt in file_tempvar
 * We read (varinit->NB_BYTE * varinit->NB_INDEX) bytes from the clear
 * file
 */
  bcrypt_fread_int (file_tempvar, varinit->NB_BYTE, varinit->NB_INDEX,
                   file_clear,varinit, mode);

  for (i = 0; i < varinit->NB_INDEX; i++)
   code_key[i] = (pass_code[i] ^ file_tempvar[i]);

  }

 tab_seed[(poskey / varinit->NB_CHAR)] = 1;
 nb_code++;

 random_key = 1;
      
 for (i = 0; i< varinit->NB_INDEX; i++)
  random_key = random_key ^ code_key[i]; 

/*
 * We generate 32 keys that will be used as a buffer to generate
 * the key we will use. 
 * Thanks to that we create a dependancy on ALL the previous key and not
 * only on the first key.
 */
 memcpy(pass_buffer[0], pass_code, varinit->NB_CHAR);
 
 for (j = 1; j<new_buffer; j++)
  {
   l=0;
   k=0;
   i=0;
   do
    {
     if (l == 0) shift = shiftfix;
      else
     shift = shift - 8; 

     pass_clear[i] = (int)((pass_buffer[j-1][k] << shift) >> shiftfix);
     
     l++;
     if (l == varinit->NB_BYTE) 
      {
       l = 0;
       k++;
      }
     i++;
    }
   while (k < varinit->NB_INDEX);

   if (bcrypt_transcription (pass_clear, pass_buffer[j], mode, varinit) == 0)
    return 0;

   if (bcrypt_add (pass_buffer[j], mode, varinit) == 0)
    return 0;

   if (bcrypt_swap (pass_buffer[j], round, mode, varinit) == 0)
    return 0;

   if (bcrypt_code (1, random_key, pass_buffer[j], mode, varinit) == 0)
    return 0;
  }

 if (1 < new_buffer)
  { 
   i = pass_code[0]%varinit->NB_INDEX;
   indexa = pass_code[i]%new_buffer;
 
   i = pass_code[1%varinit->NB_INDEX]%varinit->NB_INDEX;
   indexb = pass_code[i]%new_buffer;

   if (indexa == indexb) indexb = (indexb + 1)%new_buffer;
 
/*
 * indexb will start with the last bit rather than the first bit.
 * this is in the unlikely event that indexa = indexb
 * It could happened if new_buffer = 1
 */
   for (i=0; i<varinit->NB_INDEX; i++)
    {
     pass_code[i] = pass_buffer[indexa][i]&
                    pass_buffer[indexb][(varinit->NB_INDEX - 1 - i)];
    }
  }
 else
  {
   indexa = 0;
   indexb = 0;
   memcpy(pass_code, pass_buffer[indexa], varinit->NB_CHAR);
  }      
 
 j=(1 % varinit->NB_INDEX);

 do
  {

/*
 *  We find where we are going to insert the filter 
 */
   pos = pass_code[j]%length_seed;
   j = (j + 1)%varinit->NB_INDEX;

   while (tab_seed[pos] == 1)
    pos = (pos + 1) % length_seed;

   tab_seed[pos]=1;
   pos = pos * varinit->NB_CHAR;
   pos_read = pos;
   pos_write = pos;

   if (pos_read > poskey)
    {
     if (0 == choice)
      pos_read = pos_read - varinit->NB_CHAR;
     else
      pos_write = pos_write - varinit->NB_CHAR;
    }

   if (pos_read < block_crypt)
    {
     if ((pos_read + varinit->NB_CHAR) <= block_crypt)
      {
/*
 * we go to the position 'pos' in the file to crypt
 */
       fseek (file_clear, (pos_crypt + pos_read), 0);
	
/*
 * We save the file data to crypt in file_tempvar
 * We read (varinit->NB_BYTE * varinit->NB_INDEX) bytes from the clear
 * file
 */
       bcrypt_fread_int (file_tempvar, varinit->NB_BYTE, varinit->NB_INDEX,
                         file_clear,varinit, mode);
	
/*
 * We go the the same position in the file that will
 * receive the crypted data
 */	
       fseek (file_code, (pos_crypt_write + pos_write), 0);

       for (i = 0; i < varinit->NB_INDEX; i++)
        file_tempvar[i] ^= pass_code[i];

       bcrypt_fwrite_int (file_tempvar, varinit->NB_BYTE, varinit->NB_INDEX,
                          file_code,varinit,mode);
	  } 
     else
      {
       rest_byte = (block_crypt - pos_read);

/*
 * we go to the position 'pos' in the file to crypt
 */
       fseek (file_clear, (pos_crypt + pos_read), 0);

       if (2 == mode)
        {
         fprintf(BCRYPTLOG,
                 "\n    End of File's number of bytes to crypt : %d.",
                 rest_byte);
         fflush(BCRYPTLOG);
        }

/*
 * We save the file data to crypt in file_tempvar
 * We read '1 * rest_byte' bytes from the clear file
 */
       bcrypt_fread_int(file_tempvar, rest_byte, 1, file_clear,varinit, mode);
	
/*
 * We go the the same position in the file that will
 * receive the crypted data
 */
       fseek (file_code, (pos_crypt_write + pos_write), 0);

       i = 0;
       tmp_rest_byte = rest_byte;

       do
        {
         file_tempvar[i] ^= pass_code[i%varinit->NB_INDEX];

         tmp_rest_byte -= varinit->NB_BYTE;
	
         i++;
        }
       while ( tmp_rest_byte > 0 );
	
       bcrypt_fwrite_int(file_tempvar, 1, rest_byte, file_code,varinit,mode);
      }
    }

    nb_code++;

/*
 * The cipher text becomes the new 'typed' passwd
 *
 * this function seems to have problems to put some long integer
 * in a string ...
 * strncpy(pass_clear,pass_code,varinit->NB_CHAR);
 * that is why I have done the following function.
 *
 * We translate the long integer from pass_code into some characters
 * in the string pass_clear
 */
    l=0;
    k=0;
    i=0;

    do
     {
      if (l == 0)
       shift = shiftfix;
      else
       shift = shift - 8; 
 
      pass_clear[i] = (int)((pass_code[k] << shift) >> shiftfix);
       
      l++;
      if (l == varinit->NB_BYTE) 
       {
        l = 0;
        k++;
       }
      i++;
     }
    while (k < varinit->NB_INDEX);


    if
   (bcrypt_transcription (pass_clear, pass_buffer[indexa], mode, varinit) == 0)
    return 0;

    if (bcrypt_add (pass_buffer[indexa], mode, varinit) == 0)
     return 0;

    if (bcrypt_swap (pass_buffer[indexa], round, mode, varinit) == 0)
     return 0;

    if (bcrypt_code (1, random_key, pass_buffer[indexa], mode, varinit) == 0)
     return 0;

    if (1 < new_buffer)
     {
      index_temp=indexa;

      i = pass_buffer[indexb][0]%varinit->NB_INDEX;
      indexa = pass_buffer[indexb][i]%new_buffer;

      i = pass_buffer[indexb][1%varinit->NB_INDEX]%varinit->NB_INDEX;
      indexb = pass_buffer[indexb][i]%new_buffer;

/* 
 * We don't want to use the last key used to crypt
 */
      if (indexa == index_temp) indexa = (indexa + 1)%new_buffer;
      if (indexb == index_temp) indexb = (indexb + 1)%new_buffer;
 
      if (indexa == indexb) indexb = (indexb + 1)%new_buffer;
  
/*
 * indexb will start with the last bit rather than the first bit.
 * this is in the unlikely event that indexa = indexb
 * It could happened if new_buffer = 1
 */
      for (i=0; i<varinit->NB_INDEX; i++)
       {
        pass_code[i] = pass_buffer[indexa][i]&
                       pass_buffer[indexb][(varinit->NB_INDEX - 1 - i)];
       }
     }
    else
     memcpy(pass_code, pass_buffer[indexa], varinit->NB_CHAR);
 

    if (varinit->PROGRESS < 50)
     {
      if (5000 <= temp_progress)
       {
        temp_progress = 1;
        varinit->PROGRESS++;
       }
      else 
       temp_progress++;
     }
  }
 while ((nb_code < length_seed) && (varinit->MISC != 1));

 bclean_string(pass_clear, varinit->NB_CHAR, mode);
 free(pass_buffer);
 free(pass_buffer_keys);
 free(pass_clear);
 free(file_tempvar);

 if (varinit->MISC == 1)
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG,"\n WARNING: BREAK SIGNAL DETECTED. STOPPING...");
     fflush(BCRYPTLOG);
    }
   return 0;
  }

 if (2 == mode)
  {
   fprintf(BCRYPTLOG,"\n -> PROB Seed FILE function Finished.");
   fflush(BCRYPTLOG);
  }
  
 return 1;

}




/*
 * 
 * === PROBABILITY SEED MEM FUNCTION ===
 *
 * This function is similar to the prob_file_seed one.
 * The only difference here is that I am working with the data
 * held in memory in an array called file_mem.
 *
 */
int
bcrypt_mem_seed_prob 
 (int choice, TYPE_INT *file_mem, int length_mem, int *tab_seed,
  int length_seed, TYPE_INT *pass_code, TYPE_INT *code_key, int round,
  int mode, globalvar *varinit)
{

 int i, j, pos, nb_code, poskey;
 int shiftfix, temp_progress = 0;
 unsigned char *pass_clear;
 TYPE_INT random_key;

 int l,k,shift = 0;

 int new_buffer, indexa, indexb, index_temp;

 TYPE_INT **pass_buffer, *pass_buffer_keys;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> PROB Seed MEM function Started.");
   fflush(BCRYPTLOG);
  }

 new_buffer = 1;
 if (1 < varinit->KEY_BUFFER)
  {
   new_buffer = varinit->KEY_BUFFER;
   if ((varinit->MISC & BMASK_BUFFER) == BMASK_BUFFER)
    {
      i = ((unsigned int)pass_code[0])%varinit->NB_INDEX;
  
      new_buffer += ((unsigned int)pass_code[i])%varinit->KEY_BUFFER;    

      if (2 == mode)
       {
        fprintf(BCRYPTLOG, "\n     Dynamic Buffer Flag Detected.");
        fprintf(BCRYPTLOG, "\n     Old Key buffer size: '%d'",
                varinit->KEY_BUFFER);
        fprintf(BCRYPTLOG, "\n     New Key buffer size: '%d'",new_buffer);
        fflush(BCRYPTLOG);
       }
    }
  }

 pass_buffer= (TYPE_INT **) malloc(new_buffer * sizeof(TYPE_INT *));
 pass_buffer_keys= (TYPE_INT *)malloc(new_buffer*varinit->NB_CHAR);         

 pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);

 if ((NULL == pass_buffer) || (NULL == pass_buffer_keys) ||
     (NULL == pass_clear)) 
  {
   if(mode>= 1)
    fprintf(BCRYPTLOG, "\n ERROR.\nOUT OF MEMORY! (bcrypt_mem_seed_prob)\n");

   free(pass_buffer);
   free(pass_buffer_keys);
   free(pass_clear);

   return 0;
  }

 nb_code=0;

 for(i=0; i<new_buffer; i++)
  pass_buffer[i]= pass_buffer_keys+(i*varinit->NB_INDEX);
 
 for (i=0; i<length_seed; i++)
  tab_seed[i] = 0;

 /*
 * I do not start with the first pass_code generated
 * This is because I may also use it with bcrypt_file_shuffle
 *
 * We translate the long integer from pass_code into some characters
 * in the string pass_clear
 */
 l=0;
 k=0;
 i=0;
 shiftfix = (varinit->NB_BITS) - 8;
 do
  {
   if (l == 0) shift = shiftfix;
    else
   shift = shift - 8; 

   pass_clear[i] = (int)((pass_code[k] << shift) >> shiftfix);
     
   l++;
   if (l == varinit->NB_BYTE) 
    {
     l = 0;
     k++;
    }
   i++;
  }
 while (k < varinit->NB_INDEX);

 if (bcrypt_transcription (pass_clear, pass_code, mode, varinit) == 0)
  {
   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   free(pass_buffer);
   free(pass_buffer_keys);
   free(pass_clear);
   return 0;
  }

 if (bcrypt_add (pass_code, mode, varinit) == 0)
  {
   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   free(pass_buffer);
   free(pass_buffer_keys);
   free(pass_clear);
   return 0;
  }

 if (bcrypt_swap (pass_code, round, mode, varinit) == 0)
  {
   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   free(pass_buffer);
   free(pass_buffer_keys);
   free(pass_clear);
   return 0;
  }

/*
 *  We find where we are going to insert the Random key
 */
 poskey = pass_code[0]%(length_seed - 1);
 tab_seed[poskey] = 1;
 poskey = (poskey * varinit->NB_INDEX);

 if (choice == 0)
  {

/*
 * We slide the data to the right to be able to insert the random
 * key after
*/ 
   for (i = length_mem - 1; (i - varinit->NB_INDEX) >= poskey; i--)
    file_mem[i] = file_mem[i - varinit->NB_INDEX];

/*
 * And we finaly insert the random key !
 */
   for (i = poskey, j = 0; i < (poskey + varinit->NB_INDEX); i++, j++)
    file_mem[i] = (pass_code[j] ^ code_key[j]);

  }
 else
  {

/*
 * We save the file data to crypt in file_tempvar
 * We read (varinit->NB_BYTE * varinit->NB_INDEX) bytes from the clear
 * file
 */
    for (i = 0, j = poskey; i < varinit->NB_INDEX; i++, j++)
     code_key[i] = (pass_code[i] ^ file_mem[j]);
  }

 nb_code++;
/*
 * Random Key can be setup to what ever you want in fact..
 * as long as it is initialised.
 * I choosed one in the past because I was doing a multiplication.
 * I keep it now because it's not worse than random_key = 0; ;o)
 */
 random_key = 1;
      
 for (i = 0; i< varinit->NB_INDEX; i++)
  random_key = random_key ^ code_key[i]; 

/*
 * We generate 32 keys that will be used as a buffer to generate
 * the key we will use. 
 * Thanks to that we create a dependancy on ALL the previous key and not
 * only on the first key.
 */

 memcpy(pass_buffer[0], pass_code, varinit->NB_CHAR);

 for (j = 1; j<new_buffer; j++)
  {
   l=0;
   k=0;
   i=0;
   do
    {
     if (l == 0) shift = shiftfix;
      else
     shift = shift - 8; 

     pass_clear[i] = (int)((pass_buffer[j-1][k] << shift) >> shiftfix);
     
     l++;
     if (l == varinit->NB_BYTE) 
      {
       l = 0;
       k++;
      }
     i++;
    }
   while (k < varinit->NB_INDEX);

   if (bcrypt_transcription (pass_clear, pass_buffer[j], mode, varinit) == 0)
    {
     bclean_string(pass_clear, varinit->NB_CHAR, mode);
     free(pass_buffer);
     free(pass_buffer_keys);
     free(pass_clear);
     return 0;
    }


   if (bcrypt_add (pass_buffer[j], mode, varinit) == 0)
    {
     bclean_string(pass_clear, varinit->NB_CHAR, mode);
     free(pass_buffer);
     free(pass_buffer_keys);
     free(pass_clear);
     return 0;
    }

   if (bcrypt_swap (pass_buffer[j], round, mode, varinit) == 0)
    {
     bclean_string(pass_clear, varinit->NB_CHAR, mode);
     free(pass_buffer);
     free(pass_buffer_keys);
     free(pass_clear);
     return 0;
    }


   if (bcrypt_code (1, random_key, pass_buffer[j], mode, varinit) == 0)
    {
     bclean_string(pass_clear, varinit->NB_CHAR, mode);
     free(pass_buffer);
     free(pass_buffer_keys);
     free(pass_clear);
     return 0;
    }

  }

 if (1 < new_buffer)
  {
   i = pass_code[0]%varinit->NB_INDEX;
   indexa = pass_code[i]%new_buffer;

   i = pass_code[1%varinit->NB_INDEX]%varinit->NB_INDEX;
   indexb = pass_code[i]%new_buffer;

   if (indexa == indexb) indexb = (indexb + 1)%new_buffer;
 
/*
 * indexb will start with the last bit rather than the first bit.
 * this is in the unlikely event that indexa = indexb
 * It could happened if new_buffer = 1
 */
   for (i=0; i<varinit->NB_INDEX; i++)
    {
     pass_code[i] = pass_buffer[indexa][i]&
                    pass_buffer[indexb][(varinit->NB_INDEX - 1 - i)];
    }
  }
 else   
 {
  indexa = 0;
  indexb = 0;
  memcpy(pass_code, pass_buffer[indexa], varinit->NB_CHAR);
 }     
  
 j=(1 % varinit->NB_INDEX);

 do
  {
/*
 *  We find where we are going to insert the filter 
 */
   pos = pass_code[j]%length_seed;
   j = (j + 1)%varinit->NB_INDEX;

   while (tab_seed[pos] == 1)
    pos = (pos + 1) % length_seed;

   tab_seed[pos] = 1;

   pos = (pos * varinit->NB_INDEX);

   for (i = 0; i < varinit->NB_INDEX; i++)
    {
     if (pos < length_mem)
      {
       file_mem[pos] ^= pass_code[i];
       pos++;
      }
    }

   nb_code++;

/*
 * The cipher text becomes the new 'typed' passwd
 *
 * this function seems to have problems to put some long integer
 * in a string ...
 * strncpy(pass_clear,pass_code,varinit->NB_CHAR);
 * that is why I have done the following function.
 *
 * We translate the long integer from pass_code into some characters
 * in the string pass_clear
 */
   l=0;
   k=0;
   i=0;

   do
    {
     if (l == 0) shift = shiftfix;
      else
     shift = shift - 8; 
 
     pass_clear[i] = (int)((pass_code[k] << shift) >> shiftfix);
      
     l++;
     if (l == varinit->NB_BYTE) 
      {
       l = 0;
       k++;
      }
     i++;
    }
   while (k < varinit->NB_INDEX);

   if
    (bcrypt_transcription (pass_clear, pass_buffer[indexa], mode, varinit) == 0)
    {
     bclean_string(pass_clear, varinit->NB_CHAR, mode);
     free(pass_buffer);
     free(pass_buffer_keys);
     free(pass_clear);
     return 0;
    }


   if (bcrypt_add (pass_buffer[indexa], mode, varinit) == 0)
    {
     bclean_string(pass_clear, varinit->NB_CHAR, mode);
     free(pass_buffer);
     free(pass_buffer_keys);
     free(pass_clear);
     return 0;
    }


   if (bcrypt_swap (pass_buffer[indexa], round, mode, varinit) == 0)
    {
     bclean_string(pass_clear, varinit->NB_CHAR, mode);
     free(pass_buffer);
     free(pass_buffer_keys);
     free(pass_clear);
     return 0;
    }


   if (bcrypt_code (1, random_key, pass_buffer[indexa], mode, varinit) == 0)
    {
     bclean_string(pass_clear, varinit->NB_CHAR, mode);
     free(pass_buffer);
     free(pass_buffer_keys);
     free(pass_clear);
     return 0;
    }


   if (1 < new_buffer)
    {
     index_temp=indexa;

     i = pass_buffer[indexb][0]%varinit->NB_INDEX;
     indexa = pass_buffer[indexb][i]%new_buffer;

     i = pass_buffer[indexb][1%varinit->NB_INDEX]%varinit->NB_INDEX;
     indexb = pass_buffer[indexb][i]%new_buffer;

/* 
 * We don't want to use the last key used to crypt
 */
     if (indexa == index_temp) indexa = (indexa + 1)%new_buffer;
     if (indexb == index_temp) indexb = (indexb + 1)%new_buffer;

     if (indexa == indexb) indexb = (indexb + 1)%new_buffer;
  
/*
 * indexb will start with the last bit rather than the first bit.
 * this is in the unlikely event that indexa = indexb
 * It could happened if new_buffer = 1
 */
     for (i=0; i<varinit->NB_INDEX; i++)
      {
       pass_code[i] = pass_buffer[indexa][i]&
                      pass_buffer[indexb][(varinit->NB_INDEX - 1 - i)];
      }
    }
   else
     memcpy(pass_code, pass_buffer[indexa], varinit->NB_CHAR);
    
   if (varinit->PROGRESS < 50)
    {
     if (5000 <= temp_progress)
      {
       temp_progress = 1;
       varinit->PROGRESS++;
      }
     else 
      temp_progress++;
    }
  }
 while ((nb_code < length_seed) && (varinit->MISC != 1));

 bclean_string(pass_clear, varinit->NB_CHAR, mode);
 free(pass_buffer);
 free(pass_buffer_keys);
 free(pass_clear);

 if (varinit->MISC == 1)
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG,"\n WARNING: BREAK SIGNAL DETECTED. STOPPING...");
     fflush(BCRYPTLOG);
    }
   return 0;
  }

 if (1 == choice)
  {
   for (i = poskey; i < (length_mem - varinit->NB_INDEX); i++)
    file_mem[i] = file_mem[i + varinit->NB_INDEX];
  }

 if (2 == mode)
  {
   fprintf(BCRYPTLOG,"\n -> PROB Seed MEM function Finished.");
   fflush(BCRYPTLOG);
  }

 return 1;

}




