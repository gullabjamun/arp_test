#include "printfunc.h"
#include <stdio.h>

int printinfo(unsigned char *str,int length)
{
	int i;
	for(i=0;i<length;i++)
	{
		printf("%x ",str[i]);
	}
	printf("\n");
	return 0;
}

