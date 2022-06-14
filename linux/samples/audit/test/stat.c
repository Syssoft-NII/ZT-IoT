#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/limits.h>

static int	dflag;
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

#define OPTIONS_DEF	"ds:"
#define OPTIONS_HELP	"-d -s <scale number>"

int
main(int argc, char **argv)
{
    FILE	*fin, *fout;
    int		opt, cnt, i;
    int		scale = SCALE;
    char	*ret;
    double	dt;

    while ((opt = getopt(argc, argv, OPTIONS_DEF)) != -1) {
	switch (opt) {
	case 'd':
	    dflag = 1;
	    break;
	case 's':
	    scale = atoi(optarg);
	    break;
	}
    }

    if (optind >= argc) {
	fprintf(stderr, "%s: %s <file name>\n", argv[0], OPTIONS_HELP);
	return -1;
    }
    strncpy(fileIn, argv[optind], PATH_MAX - sizeof("-stat.csv") - 1);
    strcat(fileIn, ".csv");
    sscanf(buf, "%lf\n", &dt);    printf("fileIn = %s\n", fileIn);
    if ((fin = fopen(fileIn, "r")) == NULL) {
	i = -1;
	goto err;
    }
    if ((ret = fgets(buf, 128, fin)) == NULL) {
	i = -1;	goto err;
    }
    strncpy(fileOut, argv[optind], PATH_MAX - sizeof("-stat.csv") - 1);
    strcat(fileOut, "-stat.csv");
    if ((fout = fopen(fileOut, "w+")) == NULL) {
	i = -2;	goto err;
    }
    while ((i = sscanf(buf, "%lf\n", &dt)) <= 0) {
	printf("buf=%s\n", buf);
	if (buf[0] != '#') {
	    i = -3; goto err;
	}
	if (fgets(buf, 128, fin) == NULL) {
	    i = -4; goto err;
	}
    }
    cnt = 1;
    tm[0] = mx = mn = dt; itm[0] = tm[0]*SCALE;
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
	float	fval = (float)(imn + i)/(float)scale;
	fprintf(fout, "%9.3f %d\n", fval, ipoint[i]);
	if (ipoint[i] > 0) {
	    fprintf(stdout, "%9.3f, %d\n", fval, ipoint[i]);
	}
    }
    fclose(fin);
    fclose(fout);
    return 0;
err:
    switch (i) {
    case -1:
	fprintf(stderr, "Cannot read file %s\n", fileIn); 
	break;
    case -2:
	fprintf(stderr, "Cannot write file %s\n", fileOut);
	break;
    case -3:
	fprintf(stderr, "Data format error in %s\n", fileOut);
	fprintf(stderr, "Data is %s\n", buf);
	break;
    case -4:
	fprintf(stderr, "All lines are comments\n");
	break;
    }
    return -1;
}
