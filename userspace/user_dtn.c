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
#include <ctype.h>

/* This works with tuning Module */

FILE * tunDefSysCfgPtr = 0;
FILE * tunLogPtr = 0;
void fDoSystemtuning(void);

#define htcp 		0
#define fq_codel 	1
char *aStringval[] ={"htcp", "fq_codel"};

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
#define TUNING_NUMS	7
/* Must change TUNING_NUMS if adding more to the array below */

host_tuning_vals_t aTuningNumsToUse[TUNING_NUMS] = {
    {"net.core.rmem_max",   			67108864,       	0,      	0},
    {"net.core.wmem_max",   			67108864,       	0,      	0},
    {"net.ipv4.tcp_rmem",       			4096,       87380,   33554432},
    {"net.ipv4.tcp_wmem",       			4096,       65536,   33554432},
    {"net.ipv4.tcp_mtu_probing",			   1,       	0,      	0},
    {"net.ipv4.tcp_congestion_control",	   htcp, 			0, 			0}, //uses #defines to help
    {"net.core.default_qdisc",fq_codel, 0, 0}, //uses #defines
};

void fDoSystemTuning(void)
{

	char *line = NULL;
    size_t len = 0;
    ssize_t nread;
	char *q, *r, *p = 0;
	char setting[256];
	char value[256];
	int count, intvalue, found = 0;

    while ((nread = getline(&line, &len, tunDefSysCfgPtr)) != -1) {
    	//printf("Retrieved line of length %zu:\n", nread);
		//printf("&%s&",line);
		p = line;
		q = strchr(line,' '); //search for space	
		len = (q-p) + 1;
		strncpy(setting,p,len);
		if (setting[len-1] == ' ')
			setting[--len] = 0;
		else
			setting[len] = 0;

		printf("\nsetting is ***%s***\n",setting);
		/* compare with known list now */
		for (count = 0; count < TUNING_NUMS; count++)
		{
			if (strcmp(aTuningNumsToUse[count].setting, setting) == 0) //found
			{
				q++;// move it up past the space
				q = strchr(q,' '); //search for next space	
				q++; // move to the beginning of 1st (maybe only) number
				r = strchr(q,'\n'); //search for newline
				len = (r-q) + 1;
				strncpy(value,q,len);
				value[--len] = 0;
	
				if(isdigit(value[0]))
				{
					intvalue = atoi(value);
					if(intvalue < aTuningNumsToUse[count].minimum)
					{
						if (aTuningNumsToUse[count].xDefault == 0) //only one value
						{
							printf("Current config value for *%s* is *%s* which is less than the minimum recommendation...\n",setting, value);	
							printf("You should change to the  recommended setting of *%d* for *%s*.\n",aTuningNumsToUse[count].minimum, setting);
						}
						else
							{//has min, default and max values
								//more work needed			
								printf("Current config value for *%s* is *%s* which is less than the minimum recommendation...\n",setting, value);	
								printf("You should change to the  recommended setting of *%d* for *%s*.\n",aTuningNumsToUse[count].minimum, setting);
								

							}
					}
				}	
				else
					{ //must be a string
						if (strcmp(value, aStringval[aTuningNumsToUse[count].minimum]) != 0)
						{
							printf("Current config value for *%s* is *%s* which is not the same as the recommendation...\n",setting, value);	
							printf("You should change to the  recommended setting of *%s* for *%s*.\n",aStringval[aTuningNumsToUse[count].minimum], setting);
						}
					}

				found = 1;
				break;
			}
		}

		if (!found)
			printf("ERR*** Could not find the following setting **%s**\n", setting);
		
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

