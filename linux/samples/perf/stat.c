#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>

#define TIME_MAX	10000000 /* 10,000,000, 10M */
#define SCALE	1000
double	mx, mn;
double	tm[TIME_MAX];
int	imx, imn, ilen;
int	itm[TIME_MAX];
int	*ipoint;
char	fileIn[PATH_MAX];
char	fileOut[PATH_MAX];
char	buf[1024];

int
main(int argc, char **argv)
{
    FILE	*fin, *fout;
    int		cnt, i;
    char	*ret;
    double	dt;

    if (argc < 2) {
	fprintf(stderr, "%s: <file name>\n", argv[0]);
	return -1;
    }
    strncpy(fileIn, argv[1], PATH_MAX - sizeof("-stat.csv") - 1);
    strcat(fileIn, ".csv");
    sscanf(buf, "%lf\n", &dt);    printf("fileIn = %s\n", fileIn);
    if ((fin = fopen(fileIn, "r")) == NULL) {
	i = -1;
	goto err;
    }
    if ((ret = fgets(buf, 128, fin)) == NULL) {
	i = -1;
	goto err;
    }
    strncpy(fileOut, argv[1], PATH_MAX - sizeof("-stat.csv") - 1);
    strcat(fileOut, "-stat.csv");
    if ((fout = fopen(fileOut, "w+")) == NULL) {
	i = -2;
	goto err;
    }
    sscanf(buf, "%lf\n", &dt);
    tm[0] = mx = mn = dt; itm[0] = tm[0]*SCALE;
    cnt = 1;
    printf("mx = %12.9f mn = %12.9f\n", mx, mn);
    while (fgets(buf, 128, fin) != NULL) {
	sscanf(buf, "%lf\n", &dt);
	mx = dt > mx ? dt : mx;
	mn = dt < mn ? dt : mn;
	tm[cnt] = dt;
	itm[cnt] = (int) (dt*SCALE);
	cnt++;
    }
    printf("mx = %12.9f mn = %12.9f\n", mx, mn);
    imx = (int)(mx*SCALE); imn = (int)(mn*SCALE);
    ilen = (imx - imn) + 1;
    printf("cnt = %d %d -- %d (msec) len(%d)\n", cnt, imn, imx, ilen);
    ipoint = malloc(sizeof(int)*ilen);
    memset(ipoint, 0, sizeof(int)*ilen);
    for (i = 0; i < cnt; i++) {
	int	off = itm[i] - imn;
	ipoint[off]++;
    }
    for (i = 0; i < ilen; i++) {
	fprintf(fout, "%.0f %d\n", (float)(imn + i), ipoint[i]);
    }
    fclose(fin);
    fclose(fout);
    return 0;
err:
    if (i == -1) {
	fprintf(stderr, "Cannot read file %s\n", fileIn);
    } else{
	fprintf(stderr, "Cannot write file %s\n", fileOut);
    }
    return -1;
}
