/*
 * utils.c
 *
 * UTILITIES FUNCTIONS
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
 *  Copyright 1996-2002 MARTINEZ Sylvain
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
