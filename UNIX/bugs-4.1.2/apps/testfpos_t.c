/*
 * 26 July 2002
 * London
 * Sylvain Martinez
 *
 * This is just to test if we are using a version of gcc > 2.95.2
 * as the fpos_t type has changed to a structure
 *
 *
 */


#include <stdio.h>


int main()
{
	fpos_t pos;

pos.__pos = 1;	
return 1;
}
