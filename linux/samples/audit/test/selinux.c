#include <stdio.h>
#include <selinux/selinux.h>
int
main()
{
    int	i;
    i = is_selinux_enabled();
    printf("is_selinux_enabled() returns %d\n", i);
}
