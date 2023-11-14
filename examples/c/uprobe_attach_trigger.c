#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* It's a global function to make sure compiler doesn't inline it. */
int	uprobed_add(int a, int b)
{
	return (a + b);
}

int	uprobed_sub(int a, int b)
{
	return (a - b);
}

int	main(int argc, char *argv[])
{
	int i = 0;
	for (i = 0;; i++)
	{
		/* trigger our BPF programs */
		uprobed_add(i, i + 1);
		uprobed_sub(i * i, i);
		sleep(1);
	}
}