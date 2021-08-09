#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <bits/stdint-uintn.h>
#include <bits/types.h>
/* This works with tuning Module */

FILE * tunDefSysCfgPtr = 0;
FILE * tunLogPtr = 0;
void fDoSystemtuning(void);

#define cubic 		0
#define reno 		1
#define htcp 		2
#define fq_codel 	3
char *aStringp[] ={"cubic", 
					"reno", 
					"htcp",
					"fq_codel"};

typedef struct {
    char * setting;
    uint32_t  minimum;
    uint32_t xDefault; //if default is 0, then defualt and max are nops
    uint32_t maximum;
}host_tuning_vals_t;

/* 
 * Suggestion for net.ipv4.tcp_mem...
 *
 * for tcp_mem, set it to twice the maximum value for tcp_[rw]mem multiplied by  * the maximum number of running network applications divided by 4096 bytes per  * page.
 * Increase rmem_max and wmem_max so they are at least as large as the third 
 * values of tcp_rmem and tcp_wmem.
 */

host_tuning_vals_t aTuningNumsToUse[] = {
    {"net.core.rmem_max",   			67108864,       	0,      	0},
    {"net.core.rmem_max",   			67108864,       	0,      	0},
    {"net.ipv4.tcp_rmem",       			4096,       87380,   33554432},
    {"net.ipv4.tcp_wmem",       			4096,       65536,   33554432},
    {"net.ipv4.tcp_mtu_probing",			   1,       	0,      	0},
    {"net.ipv4.tcp_congestion_control",	   cubic, 			0, 			0}, //uses #defines
    {"net.core.default_qdisc",fq_codel, 0, 0}, //uses #defines
};

void fDoSystemTuning(void)
{

	char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    while ((nread = getline(&line, &len, tunDefSysCfgPtr)) != -1) {
    	printf("Retrieved line of length %zu:\n", nread);
		printf("&%s&",line);
     //          fwrite(line, nread, 1, stdout);
           }


	fprintf(tunLogPtr, "Closing Tuning Module default system configuration file***\n");
	fclose(tunDefSysCfgPtr);
if(line)
free(line);

return;
}

int main() 
{

	char *pDevName = "/dev/tuningMod";
	char aMessage[512];

	int fd;
	int len = strlen(aMessage);
	int result;

	tunLogPtr = fopen("/tmp/tuningLog","w");
	if (!tunLogPtr)
	{
		printf("Could not open tuning Logfile, exiting...\n");
		exit(-1);
	}
	fprintf(tunLogPtr, "tuning Log opened***\n");

	tunDefSysCfgPtr = fopen("/tmp/default_sysctl_config","r");
	if (!tunDefSysCfgPtr)
	{
		printf("Could not open Tuning Module default system config file, exiting...\n");
		exit(-2);
	}

	fprintf(tunLogPtr, "Tuning Module default system configuration file opened***\n");
	fflush(tunLogPtr);

	fDoSystemTuning();
	
	fd = open(pDevName, O_RDWR,0);

	if (fd > 0)
	{
		strcpy(aMessage,"This is a message...");
		result = write(fd,aMessage,strlen(aMessage));
		if (result < 0)
			fprintf(tunLogPtr,"There was an error writing***\n");
		else
			fprintf(tunLogPtr,"***GoodW**, message written = ***%s***\n", aMessage);

		memset(aMessage,0,512);
		result = read(fd,aMessage,512);
		if (result < 0)
			fprintf(tunLogPtr,"There was an error readin***\n");
		else
			fprintf(tunLogPtr,"***GoodR**, message read = ***%s***\n", aMessage);
		
	}
		
	if (fd > 0)
		close(fd);

	fprintf(tunLogPtr, "Closing tuning Log***\n");
	fclose(tunLogPtr);

return 0;
}

