/*
 * main.c
 *
 * MAIN CRYPTOGRAPHY FUNCTIONS
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


