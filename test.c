#include <stdio.h>
int main()
{
		char *p;
		char an[10] = "abcasq123";

		p = an;
		printf("%d\n",*p+1);
		printf("%d\n",*p);
		printf("%s\n",p+2);
		printf("%d\n",*(p+1));

		return 0;
	}

