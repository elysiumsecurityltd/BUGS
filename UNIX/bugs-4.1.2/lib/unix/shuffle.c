/*
 * shuffle.c
 *
 * SHUFFLE FUNCTIONS
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
#define _BUGSCRYPT_SHUFFLE

#include "../../include/shuffle.h"
#include "../../include/main.h" 
#include "../../include/utils.h" 

/* 
 * === FILE SHUFFLE ===
 * 
 * As for the file_seed function I divide the file into blocks
 * (block's length = key's length)
 * From the last cipher password generated I am going to extract pseudo-random
 * numbers to find 3 files locations:
 * - position to crypt (pos_crypt)(I always start with the last block, cf below)
 * - position A used in the crypting process (posa)
 * - position B used in the crypting process (posb)
 * I take the blocks at the position A and B and I do a logicial operation 
 * between them (in function of the cipher password) I then add the result
 * with an Exclusive OR to the block at the position pos_crypt.
 * Then one of the blocks used to crypt (A or B) will become the new position
 * to crypt. I do this because to prevent 2 blocks to be used together to
 * crypt an other block more than once !!
 * I endup with 2 blocks uncrypted(well, in fact they've been "seeded" before !)
 * so I generate 2 news cipher password from the one sent as a parameter to 
 * this function and I add them to the block.
 * I also start this function by crypting the last block of the file this
 * is because of the way I divide the file into blocks:
 * if the key's length is 128 bits and the file's length is 260 bits
 * then I've got 3 blocks of of 128 bits, but the last block only have 4 bits
 * from the file.
 * If I was using this block in the "shuffle" process this would be week.
 * Therefore I don't use it and I crypt it at the start of this function.
 *
 * This part is really important as the file is then crypted with its own
 * content.
 */
int
bcrypt_file_shuffle
 (FILE *file_code, int *tab_shuffle, int length_shuffle, TYPE_INT *pass_code,
  int round, int block_crypt, int block_shuffle, int pos_crypt, int mode,
  globalvar *varinit)
{

 int i, j, l, k, m, pos_temp, posa, posb, saved[2], count_exit;
 int error_crypt;
 int shift = 0, shiftfix, temp_progress = 0;
 int length_temp;
 unsigned char *pass_clear;

 TYPE_INT randnumber, generator_number;
 TYPE_INT *file_tempvara, *file_tempvarb, *file_filter;

 error_crypt = 0;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Shuffle FILE function Started.");
   fflush(BCRYPTLOG);
  }

 file_tempvara = (TYPE_INT *) malloc (block_shuffle);
 file_tempvarb = (TYPE_INT *) malloc (block_shuffle);
 file_filter = (TYPE_INT *) malloc (block_shuffle);
/*
 * This will be used for the last part of the function, to generate 2 new
 * cipher Keys to crypt the last 2 blocks used to crypt.
 */
 pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);


 if ( (NULL == file_tempvara) || (NULL == file_tempvarb) ||
      (NULL == file_filter) || (NULL == pass_clear))
  {
   if (mode>= 1)
    fprintf(BCRYPTLOG, "\n ERROR.\nOUT OF MEMORY! (bcrypt_file_shuffle)\n");

   free(file_tempvara);
   free(file_tempvarb);
   free(file_filter);
   free(pass_clear);

   return 0;
 }

 length_temp = block_shuffle / varinit->NB_BYTE;
 if ((length_temp * varinit->NB_BYTE) < block_shuffle) length_temp++;

/*
 * I am going to initialise my variables from the cipher password.
 * But why should we always start with the first index of the array ?
 * So I set the index I am going to use with the cipher password.
 * Ok ... I use the first array's index for this but it still better 
 * than nothing !
 */
 i= pass_code[0] % varinit->NB_INDEX;

/*
 * I always start to crypt the last block, cf above.
 */
 pos_temp = length_shuffle - 1;
 posa = pass_code[i] % length_shuffle;
 i = (i + 1) % varinit->NB_INDEX;
 posb = pass_code[i] % length_shuffle;
 i = (i + 1) % varinit->NB_INDEX;
 generator_number = pass_code[i];

 saved[0] = 0;
 saved[1] = (1 % length_shuffle);

 for (i = 0; i < length_shuffle; i++)
  tab_shuffle[i]=0;

 do
  {

/*
 * I check if the blocks I am going to use have not been crypted
 */
   count_exit = 0;
   while ((0 == error_crypt) && ((1 == tab_shuffle[posa]) ||
         (posa == pos_temp) ))
    {
     posa = (posa + 1)%length_shuffle; 

     count_exit++;
     if (count_exit >= length_shuffle) error_crypt = 1;
    }

   count_exit = 0;
   while ((0 == error_crypt) && 
         ((1 == tab_shuffle[posb]) || (posb == pos_temp) || (posb == posa)))
    {
     posb = (posb + 1)%length_shuffle; 

     count_exit++;
     if (count_exit >= length_shuffle) error_crypt = 1;
    }

   if (0 == error_crypt)
    {

/*
 * In function of the different positions I choose what kind of 
 * logical operation I am going to use to mix the block A and B
 */
     j = (posa + posb + pos_temp) % 3;

     posa *= block_shuffle;
     posb *= block_shuffle;
     pos_temp *= block_shuffle;

/*
 * we go to the position 'posA' to get the first block
 */
     fseek (file_code, pos_crypt + posa, 0);
	
/*
 * We save the blockA which will be used to crypt in file_tempvara
 * We read varinit->NB_BYTE bytes from the clear
 * file
 */
     bcrypt_fread_int (file_tempvara, 1, block_shuffle, file_code,varinit,mode);
	
/*
 * we go to the position 'posB' to get the second block
 */
     fseek (file_code, pos_crypt + posb, 0);
	
/*
 * We save the blockB which will be used to crypt in file_tempvarb
 * We read varinit->NB_BYTE bytes from the clear
 * file
 */
     bcrypt_fread_int (file_tempvarb, 1, block_shuffle, file_code,varinit,mode);

/*
 * We go the the position where the block is going to be crypted.
 */	
     fseek (file_code, pos_crypt + pos_temp, 0);

/*
 * We save the block to crypt in file_filter
 * We read varinit->NB_BYTE bytes from the clear
 * file
 */
     if ( (pos_temp + block_shuffle) > block_crypt)
       bcrypt_fread_int (file_filter, 1, (block_crypt - pos_temp),
                         file_code,varinit,mode);
     else
       bcrypt_fread_int (file_filter, 1, block_shuffle, file_code,varinit,mode);

     switch(j)
      {
       case 0:
              for(i=0; i < length_temp; i++)
              file_filter[i] ^= (file_tempvara[i] | file_tempvarb[i]);
              break;
			
       case 1:
              for(i=0; i < length_temp; i++)
              file_filter[i] ^= ~(file_tempvara[i] | file_tempvarb[i]);
              break;

       default:
               for(i=0; i < length_temp; i++)
               file_filter[i] ^= ~(file_tempvara[i] & file_tempvarb[i]);
               break;
      }
	     
/*
 * We go back to the position where the block is going to be crypted.
 */	
     fseek (file_code, pos_crypt + pos_temp, 0);
	

     if ( (pos_temp + block_shuffle) <= block_crypt)
       bcrypt_fwrite_int (file_filter, 1, block_shuffle, file_code,
                          varinit,mode);
     else
       bcrypt_fwrite_int (file_filter, 1, (block_crypt - pos_temp),
                          file_code,varinit,mode);

     posa = posa / block_shuffle;
     posb = posb / block_shuffle;
     pos_temp = pos_temp / block_shuffle;

     tab_shuffle[pos_temp] = 1;

/*
 * I have to choose one of the blocks I mixed (A or B) to be the next
 * block to crypt. If the position that has just been crypted is an
 * odd number then the new crypt pos will be pos otherwise it is posb
 */
     if (1 == (pos_temp&1))
      pos_temp = posa;
     else
      pos_temp = posb;

     saved[0] = posa;
     saved[1] = posb;

/*
 * I get 2 new positions (A and B) from a new pseudo-random number
 */
     randnumber = long_rand(&generator_number, varinit,mode);
     posa = randnumber % length_shuffle;

     randnumber = long_rand(&generator_number, varinit,mode);
     posb = randnumber % length_shuffle;

    }

   if (varinit->PROGRESS < 100)
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
 while ((0 == error_crypt) && (varinit->MISC != 1));

 if (varinit->MISC == 1)
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG,"\n WARNING: BREAK SIGNAL DETECTED. STOPPING...");
     fflush(BCRYPTLOG);
    }

   free(file_tempvara);
   free(file_tempvarb);
   free(file_filter); 
   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   free(pass_clear);

   return 0;

 }

/*
 * We crypt the last 2 blocks used for the "shuffle" as there are no
 * more blocks that can be mixed !
 */
 for (j=0; j<2; j++)
  {

/*
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
    return 0;

   if (bcrypt_add (pass_code, mode, varinit) == 0)
    return 0;

   if (bcrypt_swap (pass_code, round, mode, varinit) == 0)
    return 0;

   i = pass_code[0] % varinit->NB_INDEX;

   pos_temp = saved[j] * block_shuffle;

/*
 * we go to the position where there is the block to crypt
 */
   fseek (file_code, pos_crypt + pos_temp, 0);
	
/*
 * We save the block to crypt in file_filter
 * We read block_shuffle bytes from the clear
 * file
 */
   if ( (pos_temp + block_shuffle) > block_crypt)
    bcrypt_fread_int (file_filter, 1, (block_crypt - pos_temp),
                      file_code,varinit,mode);
   else
    bcrypt_fread_int (file_filter, 1, block_shuffle, file_code,varinit,mode);

   for (m=0; m < length_temp; m++)
    file_filter[m] ^= pass_code[(i+m)%varinit->NB_INDEX];

/*
 * We go back to the position where the block is going to be crypted.
 */	
   fseek (file_code, pos_crypt + pos_temp, 0);

   if ( (pos_temp + block_shuffle) > block_crypt)
    bcrypt_fwrite_int (file_filter, 1, (block_crypt - pos_temp), 
                       file_code,varinit,mode);
   else
    bcrypt_fwrite_int (file_filter, 1, block_shuffle, file_code,varinit,mode);
  }

 if (2 == mode)
  {
   fprintf(BCRYPTLOG,"\n -> Shuffle FILE function Finished.");
   fflush(BCRYPTLOG);
  }

 free(file_tempvara);
 free(file_tempvarb);
 free(file_filter); 
 free(pass_clear);
 free(pass_clear);

 return 1;

}


/*
 * === MEM SHUFFLE ===
 *
 * This function is similar to the file_shuffle one.
 * The only difference here is that I am working with the data
 * held in memory in an array called file_mem.
 *
 */
int
bcrypt_mem_shuffle
 (TYPE_INT *file_mem, int length_mem, int *tab_shuffle, int length_shuffle, 
  TYPE_INT *pass_code, int round, int block_shuffle, int mode,
  globalvar *varinit)
{

 int i, j, l, k, m, pos_temp, posa, posb, saved[2];
 int count_exit, error_crypt;
 int shift = 0, shiftfix, temp_progress = 0;
 int length_temp;

 TYPE_INT randnumber, generator_number;
 unsigned char *pass_clear;

 error_crypt = 0;


 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Shuffle MEM function Started.");
   fflush(BCRYPTLOG);
  }

 length_temp = block_shuffle / varinit->NB_BYTE;
 if ((length_temp * varinit->NB_BYTE) < block_shuffle) length_temp++;

/*
 * This will be used for the last part of the function, to generate 2 new
 * cipher Keys to crypt the last 2 blocks used to crypt.
 */
 pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);

 if (NULL == pass_clear)
  {
   if (mode>= 1)
    fprintf(BCRYPTLOG, "\n ERROR.\nOUT OF MEMORY! (bcrypt_mem_shuffle)\n");

   free(pass_clear);
   return 0;
 }


/*
 * I am going to initialise my variables from the cipher password.
 * But why should we always start with the first index of the array ?
 * So I set the index I am going to use with the cipher password.
 * Ok ... I use the first array's index for this but it still better 
 * than nothing !
 */
 i= pass_code[0] % varinit->NB_INDEX;

/*
 * I always start to crypt the last block, cf above.
 */
 pos_temp = length_shuffle - 1;
 posa = pass_code[i] % length_shuffle;
 i = (i + 1) % varinit->NB_INDEX;
 posb = pass_code[i] % length_shuffle;
 i = (i + 1) % varinit->NB_INDEX;
 generator_number = pass_code[i];

 saved[0] = 0;
 saved[1] = (1 % length_shuffle);

 for (i = 0; i < length_shuffle; i++)
  tab_shuffle[i]=0;

 do
  {

/*
 * I check if the blocks I am going to use have not been crypted
 */
   count_exit = 0;
   while ((0 == error_crypt) && ( (1 == tab_shuffle[posa])
          || (posa == pos_temp) ) )
    {
     posa = (posa + 1)%length_shuffle; 
     count_exit++;
     if (count_exit >= length_shuffle) error_crypt = 1;
    }

   count_exit = 0;
   while ((0 == error_crypt) && 
	     ((1 == tab_shuffle[posb]) || (posb == pos_temp) || (posb == posa)))
    {
     posb = (posb + 1)%length_shuffle; 
     count_exit++;
     if (count_exit >= length_shuffle) error_crypt = 1;
    }

   if (0 == error_crypt)
    {

/*
 * In function of the different positions I choose what kind of 
 * logical operation I am going to use to mix the block A and B
 */
     j = (posa + posb + pos_temp) % 3;

     pos_temp = (pos_temp * block_shuffle)/ varinit->NB_BYTE;
     posa = (posa * block_shuffle) / varinit->NB_BYTE;
     posb = (posb * block_shuffle) / varinit->NB_BYTE;

     switch(j)
      {
       case 0:
              for(i=0; i < length_temp; i++)
               {
                if ((pos_temp + i) < length_mem)
                 file_mem[pos_temp + i] ^= (file_mem[posa + i] |
                                            file_mem[posb + i]);
               }
              break;
			
       case 1: 
              for(i=0; i < length_temp; i++)
               {
                if ((pos_temp + i) < length_mem)
                 file_mem[pos_temp + i] ^= ~(file_mem[posa + i] |
                                             file_mem[posb + i]);
               }
              break;
	
       default: 
               for(i=0; i < length_temp; i++)
                {
                 if ((pos_temp + i) < length_mem)
                  file_mem[pos_temp + i] ^= ~(file_mem[posa + i] &
                                              file_mem[posb + i]);
                }
               break;
      }

     pos_temp = ((pos_temp * varinit->NB_BYTE) / block_shuffle);
     posa = ((posa * varinit->NB_BYTE) / block_shuffle);
     posb = ((posb * varinit->NB_BYTE) / block_shuffle);

     tab_shuffle[pos_temp] = 1;

/*
 * I have to choose one of the blocks I mixed (A or B) to be the next
 * block to crypt. If the position that has just been crypted is an
 * odd number then the new crypt pos will be pos otherwise it is posb
 */

     if (1 == (pos_temp &1))
      pos_temp = posa;
     else
      pos_temp = posb;

     saved[0] = posa;
     saved[1] = posb;

/*
 * I get 2 new positions (A and B) from a new pseudo-random number
 */
     randnumber = long_rand(&generator_number, varinit, mode);
     posa = randnumber % length_shuffle;

     randnumber = long_rand(&generator_number, varinit, mode);
     posb = randnumber % length_shuffle;

     if (posa < 0) posa = 0 - posa;
     if (posb < 0) posb = 0 - posb;

    }

   if (varinit->PROGRESS < 100)
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
 while ((0 == error_crypt) && (varinit->MISC != 1));

 if (varinit->MISC == 1)
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG,"\n WARNING: BREAK SIGNAL DETECTED. STOPPING...");
     fflush(BCRYPTLOG);
    }

   bclean_string(pass_clear, varinit->NB_CHAR, mode);
   free(pass_clear);
   return 0;
  }



/*
 * We crypt the last 2 blocks used for the "shuffle" as there are no
 * more blocks that can be mixed !
 */
 for (j=0; j<2; j++)
  {
/*
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

   i = pass_code[0] % varinit->NB_INDEX;
   if (i < 0) i = 0 - i;

   pos_temp = ((saved[j] * block_shuffle) / varinit->NB_BYTE);

   for(m=0; m < length_temp; m++)
    {
     if ((pos_temp + m) < length_mem)
     file_mem[pos_temp + m] ^= pass_code[(i+m)%varinit->NB_INDEX];
    }

 }

 if (2 == mode)
  {
   fprintf(BCRYPTLOG,"\n -> Shuffle MEM function Finished.");
   fflush(BCRYPTLOG);
  }

 return 1;

}


/*
 * === FILE UNSHUFFLE ===
 * 
 * See the "file shuffle" function to understand this one.
 * I first do the same think as in the file shuffle function
 * except than I do not make anychange on the file at first. I
 * store the different crypt position and blocks which are supposed
 * to be used to crypt this "crypt position". I have got 3 arrays:
 * position[] = position of the block which will be crypted 
 * crypta[], cryptb[] = position of the 2 blocks used to crypt
 * For example: position[5] = 500
 *		crypta[5] = 232
 *		cryptb[5] = 1300
 * This mean than the 6e block to be crypted was the number 500 using the
 * blocks 232 and 1300 to crypt it !
 * When I have filled up these 3 arrays, I then decrypt the last 2 blocks
 * and I start from the end of the array to the beginning to de-shuffle the
 * file ... 
 * You can compare that to a "cards castle" once you've done your castle
 * if you want to remove the cards without breaking the castle you need
 * to take out the last card (on the top) and then the next one, etc
 * in a reverse order.
 * Well I'm not sure if it is a really good example, but it's late and I 
 * can't think about anything else ! ;o)
 */
int
bcrypt_file_unshuffle 
 (FILE *file_code, int *tab_shuffle, int length_shuffle, TYPE_INT *pass_code,
  int round, int block_crypt, int block_shuffle, int pos_crypt, int mode,
  globalvar *varinit)
{

 int *crypta, *cryptb, *position, index;

 int i,j, k, l, m, pos_temp, posa, posb, count_exit, error_crypt;
 int saved[2], shift = 0, shiftfix, temp_progress = 0;
 int length_temp;

 TYPE_INT randnumber, generator_number;
 TYPE_INT *file_tempvara, *file_tempvarb, *file_filter;
 unsigned char *pass_clear;

 error_crypt = 0;
 index = 0;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Unshuffle FILE function Started.");
   fflush(BCRYPTLOG);
  }

 file_tempvara = (TYPE_INT *) malloc (block_shuffle);
 file_tempvarb = (TYPE_INT *) malloc (block_shuffle);
 file_filter = (TYPE_INT *) malloc (block_shuffle);

 crypta = (int *) malloc (length_shuffle * sizeof(int));
 cryptb = (int *) malloc (length_shuffle * sizeof(int));
 position = (int *) malloc (length_shuffle * sizeof(int));

/*
 * This will be used for the last part of the function, to generate 2 new
 * cipher Keys to crypt the last 2 blocks used to crypt.
 */
 pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);

 if ( (NULL == file_tempvara) || (NULL == file_tempvarb) ||
      (NULL == file_filter) || (NULL == pass_clear) ||
      (NULL == crypta) || (NULL == cryptb) || (NULL == position))
  {
   if (mode>= 1)
    fprintf(BCRYPTLOG, "\n ERROR.\nOUT OF MEMORY! (bcrypt_file_UNshuffle)\n");

   free(file_tempvara);
   free(file_tempvarb);
   free(file_filter); 
   free(pass_clear);
   free(crypta);
   free(cryptb);
   free(position);

   return 0;
 }

 length_temp = block_shuffle / varinit->NB_BYTE;
 if ((length_temp * varinit->NB_BYTE) < block_shuffle) length_temp++;

/*
 * I am going to initialise my variables from the cipher password.
 * But why should we always start with the first index of the array ?
 * So I set the index I am going to use with the cipher password.
 * Ok ... I use the first array's index for this but it still better 
 * thna nothing !
 */
 i=pass_code[0] % varinit->NB_INDEX;

/*
 * I always start to crypt the last block, cf above.
 */
 pos_temp = length_shuffle - 1;
 posa = pass_code[i] % length_shuffle;
 i = (i + 1) % varinit->NB_INDEX;
 posb = pass_code[i] % length_shuffle;
 i = (i + 1) % varinit->NB_INDEX;
 generator_number = pass_code[i];

 saved[0] = 0;
 saved[1] = (1 % length_shuffle);

 for (i = 0; i < length_shuffle; i++)
  tab_shuffle[i]=0;

/*
 * We are going to find out how the file has been shuffled
 */
 do
  {
   count_exit = 0;
   while ((0 == error_crypt) && ( (1 == tab_shuffle[posa])
          || (posa == pos_temp) ) )
	{
     posa = (posa + 1)%length_shuffle; 
     count_exit++;
     if (count_exit >= length_shuffle) error_crypt = 1;
    }

   crypta[index] = posa;

   count_exit = 0;
   while ((0 == error_crypt) && 
	     ((1 == tab_shuffle[posb]) || (posb == pos_temp) || (posb == posa)))
	{
     posb = (posb + 1)%length_shuffle; 
     count_exit++;
     if (count_exit >= length_shuffle) error_crypt = 1;
    }

   cryptb[index] = posb;

   if (0 == error_crypt)
    {
     position[index] = pos_temp;
     tab_shuffle[pos_temp] = 1;

     if (1 == (pos_temp &1)) 
      pos_temp = posa;
     else
      pos_temp = posb;

     saved[0] = posa;
     saved[1] = posb;

     index++;
     if (index >= length_shuffle) error_crypt = 1;

     randnumber = long_rand(&generator_number, varinit, mode);
     posa = randnumber % length_shuffle;

     randnumber = long_rand(&generator_number, varinit, mode);
     posb = randnumber % length_shuffle;

    }
  }
 while ((0 == error_crypt) && (varinit->MISC != 1));

 if (varinit->MISC == 1)
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG,"\n WARNING: BREAK SIGNAL DETECTED. STOPPING...");
     fflush(BCRYPTLOG);
    }
   return 0;
  }

/*
 * Now I need to decrypt the last 2 blocks
 */
 for (j=0; j<2; j++)
  {

/*
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
    return 0;

   if (bcrypt_add (pass_code, mode, varinit) == 0)
    return 0;

   if (bcrypt_swap (pass_code, round, mode, varinit) == 0)
    return 0;

   i = pass_code[0] % varinit->NB_INDEX;

   pos_temp = saved[j] * block_shuffle;

/*
 * we go to the position where there is the block to crypt
 */
   fseek (file_code, pos_crypt + pos_temp, 0);
	
/*
 * We save the block to crypt in file_filter
 * We read varinit->NB_BYTE bytes from the clear
 * file
 */
   if ( (pos_temp + block_shuffle) > block_crypt)
    bcrypt_fread_int (file_filter, 1, (block_crypt - pos_temp),
                       file_code,varinit,mode);
   else
    bcrypt_fread_int (file_filter, 1, block_shuffle, file_code,varinit,mode);

   for(m=0; m < length_temp; m++)
     file_filter[m] ^= pass_code[(i+m)%varinit->NB_INDEX];
	    
/*
 * We go back to the position where the block is going to be crypted.
 */	
   fseek (file_code, pos_crypt + pos_temp, 0);

   if ((pos_temp + block_shuffle) > block_crypt)
    bcrypt_fwrite_int (file_filter, 1, (block_crypt - pos_temp),
                       file_code,varinit,mode);
   else
    bcrypt_fwrite_int (file_filter, 1, block_shuffle, file_code,varinit,mode);

  }

/* And now I unshuffle the file !
 * The last 2 blocks couldn't be mixed so we do - 3
 */
 for (m = length_shuffle - 3; m >= 0; m--)
  {
   j = (position[m] + crypta[m] + cryptb[m]) % 3;
   if (j < 0) j = -j;

   posa = crypta[m] * block_shuffle;
   posb = cryptb[m] * block_shuffle;
   pos_temp = position[m] * block_shuffle;

/*
 * we go to the position 'posA' to get the first block
 */
   fseek (file_code, pos_crypt + posa, 0);
	
/*
 * We save the blockA which will be used to crypt in file_tempvara
 * We read varinit->NB_BYTE bytes from the clear
 * file
 */
   bcrypt_fread_int (file_tempvara, block_shuffle, 1, file_code,varinit,mode);
	
/*
 * we go to the position 'posB' to get the second block
 */
   fseek (file_code, pos_crypt + posb, 0);
	
/*
 * We save the blockB which will be used to crypt in file_tempvarb
 * We read varinit->NB_BYTE bytes from the clear
 * file
 */
   bcrypt_fread_int (file_tempvarb, block_shuffle, 1, file_code,varinit,mode);

/*
 * We go the the position where the block is going to be crypted.
 */	
   fseek (file_code, pos_crypt + pos_temp, 0);

/*
 * We save the block to crypt in file_filter
 * We read varinit->NB_BYTE bytes from the clear
 * file
 */
   if ( (pos_temp + block_shuffle) > block_crypt)
    bcrypt_fread_int (file_filter, 1, (block_crypt - pos_temp),
                      file_code,varinit,mode);
   else
    bcrypt_fread_int (file_filter, 1, block_shuffle, file_code,varinit,mode);

   switch(j)
    {
     case 0:
            for(i=0; i < length_temp; i++)
             file_filter[i] ^= (file_tempvara[i] | file_tempvarb[i]);
            break;
			
     case 1:
            for(i=0; i < length_temp; i++)
             file_filter[i] ^= ~(file_tempvara[i] | file_tempvarb[i]);
            break;

     default:
             for(i=0; i < length_temp; i++)
              file_filter[i] ^= ~(file_tempvara[i] & file_tempvarb[i]);
             break;
    }
	     
/*
 * We go back to the position where the block is going to be crypted.
 */	
   fseek (file_code, pos_crypt + pos_temp, 0);

   if ( (pos_temp + block_shuffle) > block_crypt)
    bcrypt_fwrite_int (file_filter, 1, (block_crypt - pos_temp),
                       file_code,varinit,mode);
   else
    bcrypt_fwrite_int (file_filter, 1, block_shuffle, file_code,varinit,mode);

   if (varinit->MISC == 1)
    {
     if ((1 == mode) || (2 == mode))
      {
       fprintf(BCRYPTLOG,"\n WARNING: BREAK SIGNAL DETECTED. STOPPING...");
       fflush(BCRYPTLOG);
      }

     free(file_tempvara);
     free(file_tempvarb);
     free(file_filter);
     bclean_string(pass_clear, varinit->NB_CHAR, mode);
     free(pass_clear);
     free(crypta);
     free(cryptb);
     free(position);

     return 0;
    }

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


 free(file_tempvara);
 free(file_tempvarb);
 free(file_filter);
 bclean_string(pass_clear, varinit->NB_CHAR, mode);
 free(pass_clear);
 free(crypta);
 free(cryptb);
 free(position);

 if (2 == mode)
  {
   fprintf(BCRYPTLOG,"\n -> Unshuffle FILE function Finished.");
   fflush(BCRYPTLOG);
  }

 return 1;

}


/*
 *  MEM UNSHUFFLE
 *
 * This function is similar to the file_unshuffle one.
 * The only difference here is that I am working with the data
 * held in memory in an array called file_mem.
 *
 */
int
bcrypt_mem_unshuffle
 (TYPE_INT *file_mem, int length_mem, int *tab_shuffle, int length_shuffle, 
  TYPE_INT *pass_code, int round, int block_shuffle, int mode,
  globalvar *varinit)
{

 int *crypta, *cryptb, *position, index;

 int i,j, k, l, m, pos_temp, posa, posb, count_exit, error_crypt;
 int saved[2], shift = 0, shiftfix, temp_progress = 0;
 int length_temp;

 TYPE_INT randnumber, generator_number;
 unsigned char *pass_clear;

 error_crypt = 0;
 index = 0;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Unshuffle MEM function Started.");
   fflush(BCRYPTLOG);
  }

 crypta = (int *) malloc (length_shuffle * sizeof(int));
 cryptb = (int *) malloc (length_shuffle * sizeof(int));
 position = (int *) malloc (length_shuffle * sizeof(int));
/*
 * This will be used for the last part of the function, to generate 2 new
 * cipher Keys to crypt the last 2 blocks used to crypt.
 */
 pass_clear = (unsigned char *) malloc (varinit->NB_CHAR);

 if ((NULL == pass_clear) || (NULL == crypta) ||
    (NULL == cryptb) || (NULL == position))
  {
   if (mode>= 1)
    fprintf(BCRYPTLOG, "\n ERROR.\nOUT OF MEMORY! (bcrypt_MEM_UNshuffle)\n");

   free(pass_clear);
   free(crypta);
   free(cryptb);
   free(position);

   return 0;
  }

 length_temp = block_shuffle / varinit->NB_BYTE;
 if ((length_temp * varinit->NB_BYTE) < block_shuffle) length_temp++;

/*
 * I am going to initialise my variables from the cipher password.
 * But why should we always start with the first index of the array ?
 * So I set the index I am going to use with the cipher password.
 * Ok ... I use the first array's index for this but it still better 
 * thna nothing !
 */
 i= pass_code[0] % varinit->NB_INDEX;

/*
 * I always start to crypt the last block, cf above.
 */
 pos_temp = length_shuffle - 1;
 posa = pass_code[i] % length_shuffle;
 i = (i + 1) % varinit->NB_INDEX;
 posb = pass_code[i] % length_shuffle;
 i = (i + 1) % varinit->NB_INDEX;
 generator_number = pass_code[i];

 saved[0] = 0;
 saved[1] = (1 % length_shuffle);

 for (i = 0; i < length_shuffle; i++)
  tab_shuffle[i]=0;

/*
 * We are going to find out how the file has been shuffled
 */
 do
  {
   count_exit = 0;
   while ((0 == error_crypt) && ( (1 == tab_shuffle[posa]) ||
         (posa == pos_temp) ) )
    {
     posa = (posa + 1)%length_shuffle; 
     count_exit++;
     if (count_exit >= length_shuffle) error_crypt = 1;
    }

   crypta[index] = posa;

   count_exit = 0;
   while ( (0 == error_crypt) && 
         ((1 == tab_shuffle[posb]) || (posb == pos_temp) || (posb == posa)))
	{
     posb = (posb + 1)%length_shuffle; 
     count_exit++;
     if (count_exit >= length_shuffle) error_crypt = 1;
    }

   cryptb[index] = posb;

   if (0 == error_crypt)
    {
     position[index] = pos_temp;
     tab_shuffle[pos_temp] = 1;

     if (1 == (pos_temp % 2)) 
      pos_temp = posa;
     else
      pos_temp = posb;

     saved[0] = posa;
     saved[1] = posb;

     index++;
     if (index >= length_shuffle) error_crypt = 1;

     randnumber = long_rand(&generator_number, varinit, mode);
     posa = randnumber % length_shuffle;

     randnumber = long_rand(&generator_number, varinit, mode);
     posb = randnumber % length_shuffle;

    }
  }
 while ((0 == error_crypt) && (varinit->MISC != 1));

 if (varinit->MISC == 1)
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG,"\n WARNING: BREAK SIGNAL DETECTED. STOPPING...");
     fflush(BCRYPTLOG);
    }
   return 0;
  }

/*
 * Now I need to decrypt the last 2 blocks
 */
 for (j=0; j<2; j++)
  {
/*
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

   i = pass_code[0] % varinit->NB_INDEX;

   pos_temp = ((saved[j] * block_shuffle) / varinit->NB_BYTE);

   for(m=0; m < length_temp; m++)
    {
     if ((pos_temp + m) < length_mem)
     file_mem[pos_temp + m] ^= pass_code[(i+m)%varinit->NB_INDEX];
    }
  }

/* And now I unshuffle the file !
 * The last 2 blocks couldn't be mixed so we do - 3
 */
 for (m = length_shuffle - 3; m >= 0; m--)
  {
   j = (position[m] + crypta[m] + cryptb[m]) % 3;
   if (j < 0) j = 0 - j;

   posa = (crypta[m] * block_shuffle) / varinit->NB_BYTE;
   posb = (cryptb[m] * block_shuffle) / varinit->NB_BYTE;
   pos_temp = (position[m] * block_shuffle) / varinit->NB_BYTE;

   switch(j)
    {
     case 0:
            for(i=0; i < length_temp; i++)
             {
              if ((pos_temp + i) < length_mem)
              file_mem[pos_temp + i] ^= (file_mem[posa + i] |
                                         file_mem[posb + i]);
             }
            break;
			
     case 1: 
            for(i=0; i < length_temp; i++)
             {
              if ((pos_temp + i) < length_mem)
              file_mem[pos_temp + i] ^= ~(file_mem[posa + i] |
                                          file_mem[posb + i]);
             }
            break;
	
     default: 
             for(i=0; i < length_temp; i++)
              {
               if ((pos_temp + i) < length_mem)
               file_mem[pos_temp + i] ^= ~(file_mem[posa + i] &
                                           file_mem[posb + i]);
              }
             break;
    }

   if (varinit->MISC == 1)
    {
     if ((1 == mode) || (2 == mode))
      {
       fprintf(BCRYPTLOG,"\n WARNING: BREAK SIGNAL DETECTED. STOPPING...");
       fflush(BCRYPTLOG);
      }
     return 0;
    }

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

 bclean_string(pass_clear, varinit->NB_CHAR, mode); 
 free(pass_clear);
 free(crypta);
 free(cryptb);
 free(position); 

 if (2 == mode)
  {
   fprintf(BCRYPTLOG,"\n -> Unshuffle MEM function Finished.");
   fflush(BCRYPTLOG);
  }

 return 1;

}


