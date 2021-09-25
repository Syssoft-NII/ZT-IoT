#include <stdio.h>
#include "monlib.h"

int
main()
{
    int	i;
    monlst	*mlst;
    monlst_init();

    for (i = 0; i < 10; i++) {
	mlst = monlst_find(i);
	printf("find %d mlst = %p\n", i, mlst);
	mlst = monlst_find(i);
	printf("find %d mlst = %p\n", i, mlst);
    }
}
