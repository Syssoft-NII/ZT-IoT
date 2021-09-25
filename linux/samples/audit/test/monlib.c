#include <stdio.h>
#include "monlib.h"

monlst	*montop;
monlst	*monfree;
monlst	monlist[MAX_MONLIST];

void
monlst_init()
{
    int	i;
    monlist[0].prev = NULL;
    for (i = 0; i < MAX_MONLIST - 1; i++) {
	monlist[i].next = &monlist[i + 1];
	monlist[i + 1].prev = &monlist[i];
    }
    monlist[MAX_MONLIST - 1].next = NULL;
    monfree = monlist;
    montop = NULL;
}

monlst	*
monlst_alloc()
{
    monlst	*mlst;

    /* get entry from monfree */
    if (monfree == NULL) {
	return NULL;
    }
    mlst = monfree;
    monfree = monfree->next;
    monfree->prev = NULL;
    mlst->next = montop;
    mlst->prev = NULL;
    /* insert the entry to montop */
    if (montop != NULL) {
	montop->prev = mlst;
    }
    montop = mlst;
    return mlst;
}

void
monlst_free(monlst *mlst)
{
    /* remove the entry from montop list  */
    if (mlst->prev == NULL) {
	montop = mlst->next;
    } else {
	mlst->prev->next = mlst->next;
    }
    mlst->prev = NULL;
    /* insert the entry to monfree list */
    mlst->next = monfree;
    monfree->prev = mlst;
    monfree = mlst;
}

monlst *
monlst_find(int seq)
{
    monlst	*cur;
    for (cur = montop; cur != NULL; cur = cur->next) {
	if (cur->seq == seq) goto find;
    }
    /* not found */
    printf("Not found %d\n", seq);
    cur = monlst_alloc();
    cur->seq = seq;
find:
    return cur;
}
