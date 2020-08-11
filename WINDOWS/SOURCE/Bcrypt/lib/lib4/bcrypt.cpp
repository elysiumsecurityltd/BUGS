/*
 * main.c
 *
 * MAIN CRYPTOGRAPHY FUNCTIONS
 *
 *  B U G S - LIBRARY
 *
 *  DYNAMIC CRYPTOGRAPHY ALGORITHM
 *  Version 4.0.0 - "ARMISTICE"
 *  19 November 2000
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
 *   UNIX Consultant
 *   Passion: Cryptology and Network Security
 *   emails: martinez@encryptsolutions.com
 *	         bugs@bcrypt.com
 *	         martinez@asi.fr
 *           sylvain.martinez@netcourrier.com
 *   BUGS Products URL	: http://www.bcrypt.com
 *   BUGS Company URL 	: http://www.encryptsolutions.com
 *   Personal URL     	: http://www.asi.fr/~martinez
 *
 *  Copyright 1996-2000 MARTINEZ Sylvain
 *  THIS IS FREE SOFTWARE; YOU CAN REDISTRIBUTE IT AND/OR MODIFY IT UNDER
 *  THE TERMS OF THE GNU GENERAL PUBLIC LICENSE, see the file COPYING.
 */

/*
 * This is my own header
 */
#define _BUGSCRYPT_MAIN
#define _BUGSCRYPT_DLL

#include "../../include/main.h"
#include "../../include/utils.h"

/*
 * This allows the library to be compiled on Windows 9x/2K/NT
 */
#if defined(__WIN32__)
 #pragma hdrstop
 #include <condefs.h>
 #pragma argsused

 int WINAPI DllEntryPoint(HINSTANCE hinst, unsigned long reason, void*)
  {
   return 1;
  }
#endif

/*
 * === TEST LENGTH FUNCTION ===
 *
 * To use when the key is a typed passwd
 * (cipher string = when the string has been crypted)
 * to make my crypt algorithm stronger the length of the cipher string
 * has to be static and do not depend on the clear string's length.
 */
int
bcrypt_test_length
 (unsigned char *pass_clear, int length_pass, int mode, globalvar *varinit)
{
 unsigned int i, j, nb, x, y, xy, indexa, indexb;
 unsigned char *pass_clear_saved;

 if (2 == mode) 
  {
   fprintf(BCRYPTLOG,"\n\n -> Test length function started.");
   fprintf(BCRYPTLOG, "\n    Length of the input string : %d.",length_pass);
   fflush(BCRYPTLOG);
  }

/*
 * Check if we have to add some characters
 */
 if (length_pass < varinit->NB_CHAR)
  {
   if ((pass_clear_saved= (unsigned char *)malloc(varinit->NB_CHAR)) == NULL)
    {
     if (mode >= 1)
      fprintf(BCRYPTLOG,"\n ERROR.\n Out of Memory ! (bcrypt_test_length)\n");
     return 0;
   }

   for (i = 0; i < length_pass; i++)
    pass_clear_saved[i] = pass_clear[i];

   x = (unsigned int) pass_clear[length_pass - 2];
   y = (unsigned int) pass_clear[length_pass - 1];

   nb = varinit->NB_CHAR - length_pass;

   if (2 == mode)
    {
     fprintf(BCRYPTLOG, "\n    Nb of character to add : %d.",nb);
     fprintf(BCRYPTLOG, "\n    Looking for an insert position.");
     fflush(BCRYPTLOG);
    }

/*
 * We check where we can add some data in the string
 * we first test if x+y is an available position
 * if not we do that :
 * if xy=25, then x=2 and y=5
 * and we try the position x+y.
 * we do that until we find a rigth position
 */

   do
    {
     xy = x + y;

     if (xy < 0)
      xy = -xy;

/*
 * in case of a situation like this: xy = 9 and length_pass = 8
 */
     if ((xy < 10) && (xy > length_pass))
      xy = (length_pass / 2);

     x = xy / 10;
     y = xy - (x * 10);
    }
   while (xy > length_pass);
  }
 else 
  {
   if (2 == mode)
    {
     fprintf(BCRYPTLOG,"\n -> Test length function finished.");
     fflush(BCRYPTLOG);
    }
   return 1;
  }

 if (2 == mode) 
  {
   fprintf(BCRYPTLOG, " Found.\n    Insert position = %d.",xy);
   fflush(BCRYPTLOG);
  }

 for (i=0, j=xy; (i<nb) && (j < length_pass); i++, j++)
  pass_clear_saved[i] = pass_clear[j];

/*
 * Creation of new characters
 */
 for (i=xy,j=0; j<nb; i++, j++)
  {
   indexa = (unsigned int) pass_clear[j]%(length_pass - 1);
	
   indexb = (unsigned int) pass_clear[( (j+1)%(length_pass - 1) )]%(length_pass - 1);

/* 
 * It's better to use AND than XOR as the a XOR is reversible:
 * if A^B = C you know B if you know A and C. This is not true
 * with A&B = C
 */
   pass_clear[i] = pass_clear[indexa] & pass_clear[indexb];
  }

 for (i = xy + nb, j = 0; j < (length_pass - xy) ; i++, j++)
  pass_clear[i] = pass_clear_saved [j];

 if (2 == mode)
  {
   fprintf(BCRYPTLOG,"\n -> Test length function finished.");
   fflush(BCRYPTLOG);
  }

 return 1;

}


/*
 * === TRANSCRIPTION FUNCTION ===
 *
 * This Function transform the passwd letters in number
 * So I have a new string (Called "number string")
 */
int
bcrypt_transcription
 (unsigned char *pass_clear, TYPE_INT *pass_code, int mode, globalvar *varinit)
{

 int i, j, k, shift;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Passwd transcription started.");
   fflush(BCRYPTLOG);
  }

 for (i = 0; i < varinit->NB_INDEX; i++)
  pass_code[i]=0;

 i=0;
 j=0;

 do
  {
   for (k = 0; (k < varinit->NB_BYTE) &&  (j < varinit->NB_CHAR ); k++)
    {
     if (k == (varinit->NB_BYTE - 1))
      shift = 0;
     else
      shift = 8;

     pass_code[i] |= pass_clear[j];
     pass_code[i] = (pass_code[i] << shift);

     j++;
    }
   i++;
  }
 while (j < varinit->NB_CHAR );

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n -> Passwd transcription finished.");
   fflush(BCRYPTLOG);
  } 

 return 1;

}


/*
 * === ADDITIONAL FUNCTION ===
 *
 * small efficient crypt step.
 * But I prefer to do not use directly the value of the string typed by
 * the user (Called "clear string").
 * So I will add a value (value in function of the password itself) to each
 * number of the number string (see above).
 * Every time I add this number, this number will change.
 */
int 
bcrypt_add
 (TYPE_INT *pass_code, int mode, globalvar *varinit)
{
 TYPE_INT add_number = 1, shift;
 int i;
 
 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Additional function started.");
   fflush(BCRYPTLOG);
  }

 for (i = 0; i < varinit->NB_INDEX; i++)
  add_number ^= pass_code[i];

/*
 * Every time I add this number to each part of the password
 * I shift the bits of the number I add using a "shift window"
 * which is function of the password itself.
 * It's a circular shift !
 */
 for (i=0; i<varinit->NB_INDEX; i++)
  {
   shift = pass_code[i] & (varinit->NB_BITS - 1);
   add_number = (add_number >> shift) | (add_number << (varinit->NB_BITS - shift)); 

   pass_code[i] ^= add_number;

   if (2 == mode)
    {
     fprintf(BCRYPTLOG,
             "\n    Adding nb = %d.\n    Result [%d] = %d.",
             (int)add_number, i, (int) pass_code[i]);
     fflush(BCRYPTLOG);
    }

   if (varinit->MISC == 1)
    {
     if (mode >= 1)
      {
       fprintf(BCRYPTLOG,"\n WARNING: BREAK SIGNAL DETECTED. STOPPING...");
       fflush(BCRYPTLOG);
      }
	 return 0;
    }            
  }

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n -> Additional function finished.");
   fflush(BCRYPTLOG);
  }

 return 1;

}


/*
 * === SWAP FUNCTION ===
 *
 * That is the main part of the Key generator.
 * I will swap bits between them.
 * I just do like if all my number contain in my aray are a only one
 * long string of bits.
 * 
 * Each swap is between 2 bits that are distant of X bits, and X
 * will change in function of the initial passwd typed by the user.
 *
 * eg. :
 * If X=5, we swap the bit 0 with the bit 6 because 5 bits have to be between 
 * them. (in this example X doesn't change, but it does in my algo)
 *  then I start again with the last bits and (last bits - 5), 2 and 8,
 *  (last bits - 1) and (last bits - 5 - 1), 3 and 9, (last bits - 2) and
 * (last bits - 5 -2), etc...  
 * I call that a bilateral bits swapping and  each swap have a different 
 * windows (X).
 * In fact I do not just swap bits, the algo have the choice between a swap,
 * or a LOGICAL operation on the bit (XOR, AND, NOR, etc)
 *
 * You can choose the "round" of the crypt algorithm, this is the nb
 * of cycle you want to do. default is  = 2. This is the minimum to be sure
 * sure that all the bits will be swapped at least once and also had a 
 * logical operation.
 *
 * X is called modulo_session and will change at each swap !
 * the number of round is also dynamic, at the default round number specify
 * in the parameter, I also add few rounds up to 100% more. This will be 
 * function of the key !
 */
int 
bcrypt_swap
 (TYPE_INT *pass_code, int round, int mode, globalvar *varinit)
{
 int j, i, i2, i_rigth, i2_rigth, direction, start, modulo_swap, loopvar, x;
 int modulo_big, modulo_small;
 
 TYPE_INT *a, *b, tempa, tempb,  l_temp, nb;
 int indexa, indexb, cycle, operation;
 int modulo_session;
 
 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Bcrypt_swap function Started.");
   fflush(BCRYPTLOG);
  }

 if (round <= 0) 
  {
   if (2 == mode)
    {
     fprintf(BCRYPTLOG, "\n Wrong Round value. Forcing to '2'");
     fflush(BCRYPTLOG);
    }
   round = 2;
  }

 l_temp = 1;


 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n    Nb of default Round = %d.",round);
   fprintf(BCRYPTLOG, "\n    Shift Window for division = %d.",varinit->NB_SHIFT);
   fflush(BCRYPTLOG);
  }
 
/*
 * Here we go to swap bits !
 */

/*
 * I alternate swap from the right/left and from the left/right
 * The starting position change in function of the password itself.
 * I do that because I noticed that if I only do from the left,
 * the bits in the left may be push on the rigth, rather to have
 * as chance to stay on the left or in the middle as to be on
 * the rigth.
 * As well, this could be a weak point of the algorithm if I did not do that
 * because you could find a sequence in the swapping bit.
 */
   
/*
 * Pseudo-Random initialisation of some variables.
 */

 start = pass_code[0]&1;

 direction = pass_code[(1%varinit->NB_INDEX)]&1;

 modulo_swap = pass_code[(2%varinit->NB_INDEX)]&1;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n    INIT SWAP variables:");
   fflush(BCRYPTLOG);
  }
  
 if ((varinit->MISC & BMASK_ROUND) == BMASK_ROUND)
  { 
   round = round + (pass_code[(3%varinit->NB_INDEX)]%(round + 1));

   if (2 == mode)
    {
     fprintf(BCRYPTLOG, "\n    Dynamic Round Flag Detected.");
     fprintf(BCRYPTLOG, "\n         New nb of Round='%d'",round);
     fflush(BCRYPTLOG);
    }

  }
 else
  {
   if (2 == mode)
    {
     fprintf(BCRYPTLOG, "\n         Nb of Round='%d'",round);
     fflush(BCRYPTLOG);
    }
  }

/*
 * Thanks to that I'm sure I will have BIG swap windows
 * and SMALL swap windows
 * The type of windows swap I start with (BIG or SMALL)
 * is function of the password itself
 */
 modulo_big = varinit->KEYLENGTH - 2;
 modulo_small = (varinit->KEYLENGTH - 2) / 2;
 
 if (modulo_swap == 0) 
  modulo_swap = modulo_big;
 else 
  modulo_swap = modulo_small;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n         Operation='%d'.",start);
   fprintf(BCRYPTLOG, "\n         Direction='%d'.",direction);
   fprintf(BCRYPTLOG, "\n         Modulo_swap='%d'.",modulo_swap);
   fflush(BCRYPTLOG);
  }

/*
 * Here starts the main part of the function
 * With a round of 2, all bits will be once swapped and had a
 * LOGICAL operation.
 */

 for (loopvar=0; loopvar < round; loopvar++)
  {

   operation = start;
   i = 0; 
   cycle = 0;

   do
    {
/*
 * I set the swap windows
 */
     if ((varinit->MISC & BMASK_SWAP) == BMASK_SWAP)
      { 
       modulo_session = (unsigned int)
       (pass_code[(i%varinit->NB_INDEX)]^
       pass_code[((i+1)%varinit->NB_INDEX)])%modulo_swap;

       if (0 == modulo_session) modulo_session = modulo_swap;
      }
     else
      modulo_session = modulo_swap;
	 
     x = pass_code[(i%varinit->NB_INDEX)]%modulo_session;

/*
 * I set the direction, will I start from the left or the right ?
 */
     direction ^=1;

/*
 * If I start from the left
 */
     if (0 == direction)
      {
/*
 * a is the addresse of the aray's index
 * where is located the bit i
 * b is the addresse of the aray's index
 * where is located the bit i+x+1
 * To know where the bits are located I use a shift
 * indeed, I have to divide i by the number of bit
 * used to store one number in the aray
 * If it is 32 bits, I have to divide by 32
 * but I can do a right shift of 5 instead because
 * doing that is the same thing.
 */
       a = &pass_code[i >> varinit->NB_SHIFT];

/*
 * if the second bit is out of the range, I take it
 * from the BEGINNING of the bit string ( = circular)
 */
       i2 = (i + x + 1) % varinit->KEYLENGTH;

       b = &pass_code[i2 >> varinit->NB_SHIFT];

/*
 * indexa = which bit in the aray's index
 * I have to swap
 * indexb = same thing
 */

       indexa = (i % varinit->NB_BITS);
       indexb = (i2 % varinit->NB_BITS);

      }
     else
      {
       i_rigth = (varinit->KEYLENGTH - 1 - i);

       a = &pass_code[i_rigth >> varinit->NB_SHIFT];


/*
 * if the second bit is out of the range, I take it
 * from the END of the bit string ( = circular)
 */
       i2_rigth = i_rigth - x - 1;

       if (i2_rigth < 0)
        i2_rigth = (varinit->KEYLENGTH + i2_rigth);

       b = &pass_code[i2_rigth >> varinit->NB_SHIFT];

       indexa = (i_rigth % varinit->NB_BITS);
       indexb = (i2_rigth % varinit->NB_BITS);

      }

/*
 * (*a >> indexa) shift the bits of the aray's index
 * where I have to swap the bit.
 * Like that, the bit that I want to swap is the bit
 * the most in the rigth.
 * We do a %2 to know if this bit is a 1 or a 0
 * Indeed, because the bit is the most in the rigth,
 * if this bit is 1, the number will be impair,
 * and a modulo of an impair number always equal
 * to 1 !
 */

     tempa = (*a >> indexa)&1;
     tempb = (*b >> indexb)&1;

/*
 * If the operation is a SWAP
 */
     if (0 == operation)
      {
/*
 * (1 << indexa) put the number 1 on the bit located
 * at the same place of the bit that will be swaped.
 * Then we take his complementary and we do a LOGICAL AND
 * that will put this number to 0, whatever was is
 * previous value (0 or 1) because we always do
 * LOGICAL AND with a 0.
 * Because all the over bits are set to 1, they
 * will not change the value of the other bits
 * in the aray.
 */
       *a &= ~(l_temp << indexa);
       *b &= ~(l_temp << indexb);

/*
 * We put the bit that we want to swap in the new
 * position where we want it to be.
 * We do a LOGICAL XOR to put it in the new
 * position.
 * Indeed, because we put in the previous
 * operation the bit to 0 :
 * 0 | 0 = 0
 * 1 | 0 = 1
 */

       *a |= (tempb << indexa);
       *b |= (tempa << indexb);
      }
     else
      {
/*
 * Pseudo-Random setting of which Logical operation I am going 
 * to use
 */

       j = pass_code[(i%varinit->NB_INDEX)]%5;
       switch (j)
        {
         case 0:
                nb = (TYPE_INT) (tempa ^ tempb);
                break;
         case 1:
                nb = (TYPE_INT) 1^(tempa | tempb);
                break;
         case 2:
                nb = (TYPE_INT) (tempa | tempb);
                break;
         case 3:
                nb = (TYPE_INT) (tempa & tempb);
                break;
         default:
                 nb = (TYPE_INT) 1^(tempa & tempb);
                 break;
        }

/*
 * (1 << indexa) put the number 1 on the bit located
 * at the same place of the bit that will be changed.
 * Then we take his complementary and we do a LOGICAL AND
 * that will put this number to 0, whatever was is
 * previous value (0 or 1) because we always do
 * LOGICAL AND with a 0.
 * Because all the over bits are set to 1, they
 * will not change the value of the other bits
 * in the aray.
 */

       *a &= ~(l_temp << indexa);

/*
 * We put the bit that we want to change in the new
 * position where we want it to be.
 * We do a LOGICAL XOR to put it in the new
 * position.
 * Indeed, because we put in the previous
 * operation the bit to 0 :
 * 0 | 0 = 0
 * 1 | 0 = 1
 */
       *a |= (nb << indexa);


      j = pass_code[((i+1)%varinit->NB_INDEX)]%5;
			 
      switch (j)
       {
        case 0:
               nb = (TYPE_INT) (tempa ^ tempb);
               break;
        case 1:
               nb = (TYPE_INT) 1^(tempa | tempb);
               break;
        case 2:
               nb = (TYPE_INT) (tempa | tempb);
               break;
        case 3:
               nb = (TYPE_INT) (tempa & tempb);
               break;
        default:
                nb = (TYPE_INT) 1^(tempa & tempb);
                break;
       }
				    
       *b &= ~(l_temp << indexb);
       *b |= (nb << indexb);            
	   
      }

/*
 * The next cycle will have a different direction and a
 * different type of operation (if it was a SWAP it will be
 * a Logical operation).
 */

     cycle ^=1;

     if ( 0 == cycle)
      {
       i++;
       operation ^= 1;

       if (modulo_swap == modulo_big)
        modulo_swap = modulo_small;
       else
        modulo_swap = modulo_big ;
      }
    }
   while ((i < varinit->KEYLENGTH) && (varinit->MISC != 1));

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
 * The first operation used in the next bunch of cycles will be
 * different from the first bunch of cycles. 
 * (I can't explain better ! ;o)
 */
   start = (start + 1)%2;
  }

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n -> Bcrypt_swap function finished.");
   fflush(BCRYPTLOG);
  }

 return 1;
	
}


/*
 * === CODE FUNCTION ===
 *
 *  To make this key generator more efficient, I've done this last part
 *
 *      I add a random number to each number of my passwd.
 *      this random number is initialised at the begining of my function.
 *       
 *       I am using long_rand() to generate other pseudo random numbers
 *       from the intial random number
 *
 *       I think it is better than the previous method:
 *       
 *      Assuming that I was shifting all the bit of the random number
 *      by 1 on the left each time that I used it to do an addition.
 *      And the bit the more on the left that should diseapear after the 
 *      shift, I was putting it on the right. 
 *
 *      That's a circle shift random number
 *
 *      eg. :
 *      Random number X = 81 and the number that I want to code are 1,2,3
 *      
 *      X=81 -> 01010001
 *      01010001 = 81
 *      10100010 = 162
 *      01000101 = 69
 *       1+81 = 82 , 2+162 = 164 , 3+69= 72
 *
 *  In fact is was not that simple, I did not shift all the bit by one each time,
 *  because it would have been useless, so I did a shift with a number each time
 *  different which depended of the password itself.
 *
 */
int
bcrypt_code
 (int choice, TYPE_INT random_key, TYPE_INT *pass_code, int mode,
  globalvar *varinit)
{
 unsigned int i, j;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> Code function started.");
   fflush(BCRYPTLOG);
  }

/*
 * choice = 0 = I want to crypt
 * choice = 1 = I want to crypt with a specific random key
 */
 if (choice == 0)
  {

/*
 * If the bit's length of the value returned by the rand() function is
 * smaller than the bit's length of TYPE_INT then the random number
 * maybe weak.
 * It is why I do 3 multiplications to be able to obtain a big random number
 */
   random_key = brand(varinit,mode);
  }        

 j = pass_code[0]%varinit->NB_INDEX;

 pass_code[j]^= random_key;

 for (i = 0; i < varinit->NB_INDEX; i++)
  {
   if (i != j)
    {
     long_rand(&random_key, varinit, mode);
     pass_code[i] ^= random_key;
    }
  }

 random_key = 0;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n -> Code function finished.");
   fflush(BCRYPTLOG);
  }
 
 return 1;

}


/*
 * seed.c
 *
 * SEED FUNCTIONS
 *
 *  B U G S - LIBRARY
 *
 *  DYNAMIC CRYPTOGRAPHY ALGORITHM
 *  Version 4.0.0  - "ARMISTICE"
 *  19 November 2000
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
 *   UNIX Consultant
 *   Interests: Cryptology and Network Security
 *   Emails: martinez@encryptsolutions.com
 *	         bugs@bcrypt.com
 *	         martinez@asi.fr
 *           sylvain.martinez@netcourrier.com
 *   BUGS Products URL	: http://www.bcrypt.com
 *   BUGS Company URL 	: http://www.encryptsolutions.com
 *   Personal URL     	: http://www.asi.fr/~martinez
 *
 *  Copyright 1996-2000 MARTINEZ Sylvain
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




/*
 * shuffle.c
 *
 * SHUFFLE FUNCTIONS
 *
 *  B U G S - LIBRARY
 *
 *  DYNAMIC CRYPTOGRAPHY ALGORITHM
 *  Version 4.0.0 - "ARMISTICE"
 *  19 November 2000
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
 *   UNIX Security Administrator (City, London, UK)
 *   Passion: Cryptology and Network Security
 *   emails: martinez@encryptsolutions.com
 *	     bugs@bcrypt.com
 *	     martinez@asi.fr
 *           sylvain.martinez@netcourrier.com
 *   BUGS Products URL	: http://www.bcrypt.com
 *   BUGS Company URL 	: http://www.encryptsolutions.com
 *   Personal URL     	: http://www.asi.fr/~martinez
 *
 *  Copyright 1996-2000 MARTINEZ Sylvain
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


/*
 * utils.c
 *
 * UTILITIES FUNCTIONS
 *
 *  B U G S - LIBRARY
 *
 *  DYNAMIC CRYPTOGRAPHY ALGORITHM
 *  Version 4.0.0 - "ARMISTICE"
 *  19 November 2000
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
 *   UNIX Security Administrator (City, London, UK)
 *   Passion: Cryptology and Network Security
 *   emails: martinez@encryptsolutions.com
 *	     bugs@bcrypt.com
 *	     martinez@asi.fr
 *           sylvain.martinez@netcourrier.com
 *   BUGS Products URL	: http://www.bcrypt.com
 *   BUGS Company URL 	: http://www.encryptsolutions.com
 *   Personal URL     	: http://www.asi.fr/~martinez
 *
 *  Copyright 1996-2000 MARTINEZ Sylvain
 *  THIS IS FREE SOFTWARE; YOU CAN REDISTRIBUTE IT AND/OR MODIFY IT UNDER
 *  THE TERMS OF THE GNU GENERAL PUBLIC LICENSE, see the file COPYING.
 */

/*
 * This is my own header
 */
#define _BUGSCRYPT_UTILS

#include "../../include/utils.h"
#include "../../include/isaac.h"
#include "../../include/wrapper.h"

/*
 * === BUGS STANDARD SECURITY LEVEL ===
 * 
 *  levels currently available:
 *  D_ = Dynamic
 *                 Keylength|Key Buffer|D_Buff|D_Round|D_Swap|D_Swap|Power
 *  BSSL_VLOW:     128      |8         |no    |no     |no    |no    |2
 *  BSSL_LOW:      128      |8         |no    |no     |yes   |yes   |3
 *  BSSL_MEDIUM:   128      |16        |yes   |yes    |yes   |yes   |4
 *  BSSL_HIGH:     256      |16        |yes   |yes    |yes   |yes   |4
 *  BSSL_VHIGH:    512      |32        |yes   |yes    |yes   |yes   |4
 *
 *                 Round|Block_Crypt|Block_Shuffle
 *  BSSL_VLOW:     2    |0          |4
 *  BSSL_LOW:      2    |0          |4
 *  BSSL_MEDIUM:   2    |0          |4
 *  BSSL_HIGH:     2    |0          |4
 *  BSSL_VHIGH:    4    |0          |4
 *
 *  default = BSSL_MEDIUM
 */									   
RETURN_TYPE 
bssl
 (int level, int *round, int *block_crypt, int *block_shuffle,
  globalvar *varinit, int mode)
{
 int power = 0;

 switch (level)
  { 
   case 0:
          power = -1;
          break;
		 
   case BSSL_VLOW:
                  varinit->KEYLENGTH = 128;
                  varinit->KEY_BUFFER = 8;
                  varinit->MISC = 0;
                  power=1;
                  *round = 2;
                  *block_crypt = 0;
                  *block_shuffle = 4;
                  break;
 				
   case BSSL_LOW:
                 varinit->KEYLENGTH = 128;
                 varinit->KEY_BUFFER = 8;
                 varinit->MISC = 0;
                 varinit->MISC ^= BMASK_SWAP;
                 varinit->MISC ^= BMASK_SHUFFLE;
                 power=3;
                 *round = 2;
                 *block_crypt = 0;
                 *block_shuffle = 4;
                 break;

   case BSSL_HIGH:
                  varinit->KEYLENGTH = 256;
                  varinit->KEY_BUFFER = 16;
                  varinit->MISC = 0;
                  varinit->MISC ^= BMASK_ROUND;
                  varinit->MISC ^= BMASK_SWAP;
                  varinit->MISC ^= BMASK_SHUFFLE;
                  varinit->MISC ^= BMASK_BUFFER;
                  power=4;
                  *round = 2;
                  *block_crypt = 0;
                  *block_shuffle = 4;
                  break;

   case BSSL_VHIGH:
                   varinit->KEYLENGTH = 512;
                   varinit->KEY_BUFFER = 32;
                   varinit->MISC = 0;
                   varinit->MISC ^= BMASK_ROUND;
                   varinit->MISC ^= BMASK_SWAP;
                   varinit->MISC ^= BMASK_SHUFFLE;
                   varinit->MISC ^= BMASK_BUFFER;
                   power=4;
                   *round = 4;
                   *block_crypt = 0;
                   *block_shuffle = 4;
                   break;

   default:		  
           varinit->KEYLENGTH = 128;
           varinit->KEY_BUFFER = 16;
           varinit->MISC = 0;
           varinit->MISC ^= BMASK_ROUND;
           varinit->MISC ^= BMASK_SWAP;
           varinit->MISC ^= BMASK_SHUFFLE;
           varinit->MISC ^= BMASK_BUFFER;
           power=4;
           *round = 2;
           *block_crypt = 0;
           *block_shuffle = 4;
           break;
  }
 
 if (power >= 0)
  binit(varinit->KEYLENGTH, varinit->RANDOM, "", 2, varinit);

 return power;
 
}

/*
 *  == ENDIAN TEST FREAD FUNCTION ===
 *
 * If the system uses Big Endian variables then the bytes will be swapped 
 * around to be Little Endian
 *
 */
int
bcrypt_fread_int
 (TYPE_INT *file_mem, int size, int nb, FILE *file_source, globalvar *varinit,
  int mode)
{
 int i,k,l,shiftfix, shift = 0, length_mem;
 unsigned char *temp_endian;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> fread_int function started.");
   fflush(BCRYPTLOG);
  }

 length_mem = (size * nb) / varinit->NB_BYTE;
 if ((length_mem * varinit->NB_BYTE) < (size * nb))
  length_mem++;

 fread(file_mem, size, nb, file_source);

/*
* ENDIAN test
*/
 if (1 == varinit->BCRYPT_ENDIAN)
  {
   if (2 == mode)
    {
     fprintf(BCRYPTLOG, "\n Reversing bytes.");
     fflush(BCRYPTLOG);
    }

   temp_endian = (unsigned char *) malloc(varinit->NB_BYTE);

   l=0;
   k=0;
   i=0;

   shiftfix=(varinit->NB_BITS) - 8;

   do
    {
     if (l == 0)
      shift = 0;
     else
      shift = shift + 8;

     temp_endian[i] = (unsigned char)((file_mem[k] << shift) >> shiftfix);

     l++;
     i++;
     if (l == varinit->NB_BYTE)
      {
       file_mem[k] = 0;
       for (i = (varinit->NB_BYTE - 1); i >= 0; i--)
        {
         file_mem[k] |= (long)temp_endian[i];
         if (i > 0) file_mem[k] = file_mem[k] << 8;
        }
       i = 0;
       l = 0;
       k++;
      }
    }
   while (k < length_mem);
  }

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n -> fread_int function finished.");
   fflush(BCRYPTLOG);
  }

 return 1;

}


/*
 *  === ENDIAN TEST FWRITE FUNCTION ===
 *
 * If the system uses Big endian then the bytes will be swapped around to be  
 * Little Endian
 *
 */
int
bcrypt_fwrite_int
 (TYPE_INT *file_mem, int size, int nb, FILE *file_source, globalvar *varinit,
  int mode)
{
 int i,k,l,shiftfix, shift = 0, length_mem;
 unsigned char *temp_endian;

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n\n -> fwrite_int function started.");
   fflush(BCRYPTLOG);
  }

 length_mem = (size * nb) / varinit->NB_BYTE;
 if ((length_mem * varinit->NB_BYTE) < (size * nb))
  length_mem++;

/*
* ENDIAN test
*/
 if (1 == varinit->BCRYPT_ENDIAN)
  {
   if (2 == mode)
    {
     fprintf(BCRYPTLOG, "\n Reversing bytes.");
     fflush(BCRYPTLOG);
    }

   temp_endian = (unsigned char *) malloc(varinit->NB_BYTE);

   l=0;
   k=0;
   i=0;

   shiftfix=(varinit->NB_BITS) - 8;

   do
    {
     if (l == 0)
      shift = 0;
     else
      shift = shift + 8;

     temp_endian[i] = (unsigned char)((file_mem[k] << shift) >> shiftfix);

     l++;
     i++;
     if (l == varinit->NB_BYTE)
      {
       file_mem[k] = 0;
       for (i = (varinit->NB_BYTE - 1); i >= 0; i--)
        {
         file_mem[k] |= (long)temp_endian[i];
         if (i > 0) file_mem[k] = file_mem[k] << 8;
        }
       i = 0;
       l = 0;
       k++;
      }
    }
   while (k < length_mem);
  }

 fwrite(file_mem, size, nb, file_source);

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n -> fwrite_int function finished.");
   fflush(BCRYPTLOG);
  }

 return 1;

}

/*
 * === POWER FUNCTION ===
 *
 * calcul a power of 2 for example
 * The one on Linux didn't return what exactly I wanted,
 * so I did mine.
 *
 */
RETURN_TYPE
bpow
 (int base, int n)
{
 int i,p;

 p = 1;
 for (i = 1; i <= n; i++)
  p = p * base;

 return p;
 
}       

/*
 * === CLEAN STRING FUNCTION ===
 *
 * fill a string of character with " "
 *
 */
RETURN_TYPE
bclean_string
 (unsigned char *to_clean, int length, int mode)
{
 int i;

 for (i = 0; i < length; i++)
  to_clean[i] = ' ';

 return 1;

}

/*
 * === CLEAN TYPE_INT FUNCTION ===
 *
 * fill an array of type TYPE_INT with "0"
 *
 */
RETURN_TYPE
bclean_typeint
 (TYPE_INT *to_clean, int length, int mode)
{
 int i;

 for (i = 0; i < length; i++)
  to_clean[i] = 0;

 return 1;
}

/*
 * === RANDON GENERATOR SELECTOR ===
 *
 * Select the random algorithm you want to use.
 * Thanks to this function I won't need to change the code
 * of the library (bcrypt_code()) if I add new RNG in the futur.
 *
 */
TYPE_INT
brand
 (globalvar *varinit, int mode)
{
 switch (varinit->RANDOM)
  {
   case 0: 
          srand((int) varinit->SEED);
          varinit->SEED = rand();
          return ((TYPE_INT)varinit->SEED); 
          break;

   default: 
           return ((TYPE_INT)isaac(varinit, mode));
           break;
  }

}

/*
 *
 * === LINEAR FEEDBACK SHIFT REGISTER FUNCTION ===
 *
 * This is a Linear Feedback Shift Register used by long_rand()
 * This function has been taken from the excellent Bruce Schneier's book
 * Applied cryptography Second Edition
 * I have just changed it a bit, the shiftregister is no longer a static 
 * variable. I needed that because I don't want to initialise the LFSR
 * always with the same variable, but in function of the password itself.
 * I believe this make it stronger.
 * I also use a different primitive polymonial modulo 2 in function of
 * the length of the "shiftregister" you are using (16, 32 or 64 bits)
 *
 */
int
lfsr
 (TYPE_INT *shiftregister, globalvar *varinit)
{
 int i;

 if (varinit->NB_BITS >= 64) 
  {

/* This is only because on my 32 bits system if I put 
 * directly 58, I have got a warning with the -Wall flag
 * and I don't like that ! ;o)
 * I have choosen a polynomial starting with 58 because with this 
 * there are 6 shifts (59,6,5,4,3,1,0)
 *  And its better than the polynomial starting with 63 as 
 *  there are only 3 shifts ! (64,4,3,1,0)
 */
	i = 58;

    *shiftregister = ((( ( (*shiftregister >> i) 
                     ^ (*shiftregister >> 5) 
                     ^ (*shiftregister >> 4) 
                     ^ (*shiftregister >> 3) 
                     ^ (*shiftregister >> 2)
                     ^ *shiftregister )) 
                     & 0x0000000000000001)  << i)
                     | (*shiftregister >> 1);

    return (*shiftregister & 0x0000000000000001);

  }

 if (varinit->NB_BITS >= 32)
  {
   *shiftregister = ((( ( (*shiftregister >> 31) 
                    ^ (*shiftregister >> 6) 
                    ^ (*shiftregister >> 4) 
                    ^ (*shiftregister >> 2) 
                    ^ (*shiftregister >> 1)
                    ^ *shiftregister )) 
                    & 0x00000001)  << 31)
                    | (*shiftregister >> 1);

   return (*shiftregister & 0x00000001);

  }

/* 
 * We then must use a 16 bits word 
 */
 *shiftregister = ((( ( (*shiftregister >> 15) 
                  ^ (*shiftregister >> 4) 
                  ^ (*shiftregister >> 2) 
                  ^ (*shiftregister >> 1) 
                  ^ *shiftregister )) 
                  & 0x0001)  << 15)
                  | (*shiftregister >> 1);

 return (*shiftregister & 0x0001);

}
	
/*
 *
 * === LONG RANDOM INTEGER GENERATOR FUNCTION ===
 *
 * Generate a long pseudo random number from a given long number
 * YOU SHOULD NOT use this as a random generator, this is not 
 * good enough for cryptography purposes.
 * I am using that to generate a sequence of pseudo random number
 * that have to be always the same if generated from the same 
 * initial number. So this, is ok for what I want to do !
 * I am using this to generate a pseudo list of block to crypt.
 * (cf bcrypt_file function)
 * I suppose that if you can generate a seed with a very big entropy
 * this function can be an "ok" random generator. But I prefer to use
 * ISAAC (see below)
 */
TYPE_INT
long_rand
 (TYPE_INT *shiftregister, globalvar *varinit, int mode)
{
 TYPE_INT v;
 int i;

 if (0 == *shiftregister)
  {
   *shiftregister=1;
 
   if (mode>=1)
    {
     fprintf(BCRYPTLOG,"\n WARNING : 0 detected and changed in the LRNG");
     fflush(BCRYPTLOG);
    }
  }

 v=0;
 for (i=0; i<varinit->NB_BITS; i++)
  {
   v <<=1;
   v |= lfsr(shiftregister, varinit);
  }

 if (2 == mode)
  {
   fprintf(BCRYPTLOG, "\n    -> Pseudo Random number generated = %d.",(int) v);
   fflush(BCRYPTLOG);
  }

 return v;

}


/*
 * === ISAAC RANDOM NUMBER GENERATOR ===
 *
 * This function is based on the work of Bob Jenkins, March 1996
 * who desinged the ISAAC algorithm.
 * I've just modified it slightly in order to be able to have a buffer
 * of random numbers (256) and to do not generate anymore until they all have
 * been used.
 * I am also using my Linear Feedback Shift Register function to re-initialise
 * the seed.
 *
 */
TYPE_INT
isaac
 (globalvar *varinit, int mode)
{

/* 
 * a ub4 is an unsigned 4-byte quantity 
 */  
 ub4 i,j;

 word k;
 ub4 a,b,c,d,e,f,g,h;
 register ub4 l,x,y;
 int temp; 
 TYPE_INT result;
  
/* 
 * Result
 */
 static ub4 randrsl[256];
 static int randcnt = 0;

/*
 *  internal state
 */
 ub4 mm[256];
 ub4 aa=0, bb=0, cc=0;

 aa=bb=cc=(ub4)0;

/*
 * The golden ration
 */
 a=b=c=d=e=f=g=h=0x9e3779b9;

 if (varinit->NB_BYTE < 4) 
  {
   if ((1 == mode) || (2 == mode))
    {
     fprintf(BCRYPTLOG, "\n WARNING: Forcing use of Standard C RNG");
     fprintf(BCRYPTLOG, "\n          because Type of Integer < 32 bits");
     fflush(BCRYPTLOG);
    }

    return rand();
  }

 temp = varinit->NB_BYTE / sizeof(ub4);

 if (((randcnt + temp) < 256) && (randcnt != 0))
  {
   randcnt = randcnt + temp;
   j = 0;
   result = 0;
   do
    {
     if (0 != j)
      result = result << sizeof(ub4);

     result |= randrsl[randcnt];
     j++;
    }
   while ( j < temp);
	  
   return result;
  }
 else
  randcnt = 0;

 for (i=0; i<256; ++i)
  mm[i]=randrsl[i]=(ub4) long_rand(&varinit->SEED, varinit, mode);

/*
 * Randinit
 * Scramble it
 */
 for (k=0; k<4; ++k)
  mix(a,b,c,d,e,f,g,h);

/*
 * fill in mm[] with messy stuff
 */
 for (k=0; k<256; k+=8)
  {
   a+=randrsl[k  ]; b+=randrsl[k+1]; c+=randrsl[k+2]; d+=randrsl[k+3];
   e+=randrsl[k+4]; f+=randrsl[k+5]; g+=randrsl[k+6]; h+=randrsl[k+7];
   mix(a,b,c,d,e,f,g,h);
   mm[k  ]=a; mm[k+1]=b; mm[k+2]=c; mm[k+3]=d;
   mm[k+4]=e; mm[k+5]=f; mm[k+6]=g; mm[k+7]=h;
  }

/*
 *  do a second pass to make all of the seed affect all of mm 
 */
 for (k=0; k<256; k+=8)
  {
   a+=mm[k  ]; b+=mm[k+1]; c+=mm[k+2]; d+=mm[k+3];
   e+=mm[k+4]; f+=mm[k+5]; g+=mm[k+6]; h+=mm[k+7];
   mix(a,b,c,d,e,f,g,h);
   mm[k  ]=a; mm[k+1]=b; mm[k+2]=c; mm[k+3]=d;
   mm[k+4]=e; mm[k+5]=f; mm[k+6]=g; mm[k+7]=h;
  }

/*
 * ISAAC
 */
 for (i=0; i<2; i++)
  {
/*
 *  cc just gets incremented once per x results (here x = temp)
 */
   cc = cc + 1;
   
/*
 * Then combined with bb
 */
   bb = bb + cc;  

   for (l=0; l<256; ++l)
   {
    x = mm[l];
    switch (l%4)
     {
      case 0: aa = aa^(aa<<13); break;
      case 1: aa = aa^(aa>>6); break;
      case 2: aa = aa^(aa<<2); break;
      case 3: aa = aa^(aa>>16); break;
     }
    aa         = mm[(l+128)%256] + aa;
    mm[l] = y  = mm[(x>>2)%256] + aa + bb;
    randrsl[l] = bb = mm[(y>>10)%256] + x;

/* Note that bits 2..9 are chosen from x but 10..17 are chosen
 * from y.  The only important thing here is that 2..9 and 10..17
 * don't overlap.  2..9 and 10..17 were then chosen for speed in
 * the optimized version (rand.c) 
 * 
 * See http://burtleburtle.net/bob/rand/isaac.html
 * for further explanations and analysis. 
 */
   }
  }

 result = (TYPE_INT) 0;

 j = 0;
 do
  {
   if (0 != j) result = result << sizeof(ub4);
   result |= randrsl[(int)clock()%256];
   j++;
  }
 while ( j < temp);
      
 randcnt = randcnt + temp;
    
 return result;
 
}
/*
 * misc.c
 *
 * MISCALLENAENOUS FUNCTIONS
 *
 *  B U G S - LIBRARY
 *
 *  DYNAMIC CRYPTOGRAPHY ALGORITHM
 *  Version 4.0.0 - "ARMISTICE"
 *  19 November 2000
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
 *   UNIX Security Administrator (City, London, UK)
 *   Passion: Cryptology and Network Security
 *   emails: martinez@encryptsolutions.com
 *	     bugs@bcrypt.com
 *	     martinez@asi.fr
 *           sylvain.martinez@netcourrier.com
 *   BUGS Products URL	: http://www.bcrypt.com
 *   BUGS Company URL 	: http://www.encryptsolutions.com
 *   Personal URL     	: http://www.asi.fr/~martinez
 *
 *  Copyright 1996-2000 MARTINEZ Sylvain
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

 while (pos_old < pos)
  {
   fread (var->name, varinit->USER_LENGTH, 1, file_old);
   fread (var->pass, varinit->NB_CHAR, 1, file_old);
   fwrite(var->name, varinit->USER_LENGTH, 1, file_s);
   fwrite(var->pass, varinit->NB_CHAR, 1, file_s);
   fgetpos (file_old, &pos_old);
  }

 pos_old = pos_old + varinit->USER_LENGTH + varinit->NB_CHAR;
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

/*
 * wrapper.c
 *
 * WRAPPER FUNCTIONS
 *
 *  B U G S - LIBRARY
 *
 *  DYNAMIC CRYPTOGRAPHY ALGORITHM
 *  Version 4.0.0 - "ARMISTICE"
 *  19 November 2000
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
 *   UNIX Security Administrator (City, London, UK)
 *   Passion: Cryptology and Network Security
 *   emails: martinez@encryptsolutions.com
 *	     bugs@bcrypt.com
 *	     martinez@asi.fr
 *           sylvain.martinez@netcourrier.com
 *   BUGS Products URL	: http://www.bcrypt.com
 *   BUGS Company URL 	: http://www.encryptsolutions.com
 *   Personal URL     	: http://www.asi.fr/~martinez
 *
 *  Copyright 1996-2000 MARTINEZ Sylvain
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

