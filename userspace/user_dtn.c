static const char *__doc__ = "Tuning Module Userspace program\n"
        " - Finding xdp_stats_map via --dev name info\n"
	" - Has a Tuning Module counterpart in the kernel\n";

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
#include <getopt.h>
#include <pthread.h>
#include <signal.h>

#define WORKFLOW_NAMES_MAX	4

static void gettime(time_t *clk, char *ctime_buf) 
{
    *clk = time(NULL);
	ctime_r(clk,ctime_buf);
    ctime_buf[24] = ':';
}

FILE * tunLogPtr = 0;
void fDoGetUserCfgValues(void);
void fDoSystemtuning(void);
void fDo_lshw(void);
static char *pUserCfgFile = "user_config.txt";
static int gInterval = 2; //default
static char gTuningMode = 'n';
static char gApplyDefSysTuning = 'n';
static char netDevice[128];


enum workflow_phases {
	STARTING,
    ASSESSMENT,
    LEARNING,
    TUNING,
};

static enum workflow_phases current_phase = STARTING;

static const char *workflow_names[WORKFLOW_NAMES_MAX] = {
        "STARTING",
        "ASSESSMENT",
        "LEARNING",
        "TUNING",
};

const char *phase2str(enum workflow_phases phase)
{
        if (phase < WORKFLOW_NAMES_MAX)
                return workflow_names[phase];
        return NULL;
}

#define SIGINT_MSG "SIGINT received.\n"
void sig_int_handler(int signum, siginfo_t *info, void *ptr)
{
    write(STDERR_FILENO, SIGINT_MSG, sizeof(SIGINT_MSG));
    fprintf(tunLogPtr,"Caught SIGINT, exiting...\n");
    fclose(tunLogPtr);
    exit(0);
}

void catch_sigint()
{
    static struct sigaction _sigact;

    memset(&_sigact, 0, sizeof(_sigact));
    _sigact.sa_sigaction = sig_int_handler;
    _sigact.sa_flags = SA_SIGINFO;

    sigaction(SIGINT, &_sigact, NULL);
}

/* start of bpf stuff  ****/
#ifndef PATH_MAX
#define PATH_MAX    4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

#include <locale.h>
#include <time.h>

//#include <bpf/bpf.h>
//Looks like I don't need <bpf/bpf.h> - I do need libbpf.h below though.
//Looks like because of the ringbuf stuff
#include "../../libbpf/src/libbpf.h"
/* Lesson#1: this prog does not need to #include <bpf/libbpf.h> as it only uses
 * the simple bpf-syscall wrappers, defined in libbpf #include<bpf/bpf.h>
 */

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_kern_user.h"
#include "bpf_util.h" /* bpf_num_possible_cpus */

static int read_buffer_sample(void *ctx, void *data, size_t len) 
{
	time_t clk;
	char ctime_buf[27];
	struct event *evt = (struct event *)data;

	gettime(&clk, ctime_buf);
  	fprintf(tunLogPtr,"%s %s: %s::: %lld %lld %lld %lld %lld %lld\n", ctime_buf, phase2str(current_phase), "MetaData from Collector Module", evt->numb1, evt->numb2,evt->numb3,evt->numb4,evt->numb5,evt->numb6);

	return 0;
}

static const struct option_wrapper long_options[] = {
    {{"help",        no_argument,       NULL, 'h' },
     "Show help", false},

    {{"dev",         required_argument, NULL, 'd' },
     "Operate on device <ifname>", "<ifname>", true},

    {{"quiet",       no_argument,       NULL, 'q' },
     "Quiet mode (no output)"},

    {{0, 0, NULL,  0 }}
};

typedef struct {
		int argc;
		char ** argv;
} sArgv_t;

void * fDoRunBpfCollection(void * vargp) 
{

    struct bpf_map_info map_expect = { 0 };
    struct bpf_map_info info = { 0 };
    char pin_dir[PATH_MAX];
    int buffer_map_fd;
    struct ring_buffer *rb;
    int len, err;
    time_t clk;
    char ctime_buf[27];

    struct config cfg = {
        .ifindex   = -1,
        .do_unload = false,
    };

	sArgv_t * sArgv = (sArgv_t * ) vargp;

    /* Cmdline options can change progsec */
    parse_cmdline_args(sArgv->argc, sArgv->argv, long_options, &cfg, __doc__);

	/* Required option */
    if (cfg.ifindex == -1) {
        fprintf(stderr, "ERR: required option --dev missing\n\n");
        usage(sArgv->argv[0], __doc__, long_options, (sArgv->argc == 1));
		fflush(stderr);
		return (void *)1;
        //return EXIT_FAIL_OPTION;
    }

	/* Use the --dev name as subdir for finding pinned maps */
    len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
    if (len < 0) {
        fprintf(stderr, "ERR: creating pin dirname\n");
		fflush(stderr);
		return (void *)2;
        //return EXIT_FAIL_OPTION;
    }

	buffer_map_fd = open_bpf_map_file(pin_dir, "int_ring_buffer", &info);
    if (buffer_map_fd < 0) {
        fprintf(stderr, "ERR: fail to get buffer map fd\n");
		fflush(stderr);
		return (void *)3;
        //return EXIT_FAIL_BPF;
    }

    /* check map info, e.g. datarec is expected size */
    map_expect.max_entries = 1 << 14;
    err = check_map_fd_info(&info, &map_expect);
    if (err) {
        fprintf(stderr, "ERR: map via FD not compatible\n");
		fflush(stderr);
		return (void *)4;
    }

    if (verbose) {
        printf("\nCollecting stats from BPF map\n");
        printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
               " max_entries:%d\n",
               info.type, info.id, info.name, info.max_entries
               );
    }

    rb = ring_buffer__new(buffer_map_fd, read_buffer_sample, NULL, NULL);

    if (!rb)
    {
	    fprintf (stderr,"can't create ring buffer struct****\n");
		fflush(stderr);
		return (void *)6;
    }

    gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: Starting communication with Collector Module...***\n", ctime_buf, phase2str(current_phase));
	while (1) {
			ring_buffer__consume(rb);
			sleep(gInterval);
	}
    	
	return (void *)7;
}


/* End of bpf stuff ****/

/* Must change NUMUSERVALUES below if adding more values */
#define NUMUSERVALUES	4
#define USERVALUEMAXLENGTH	256
typedef struct {
	char aUserValues[USERVALUEMAXLENGTH];
	char default_val[32];
	char cfg_value[32];
} sUserValues_t[NUMUSERVALUES];

sUserValues_t userValues = {{"evaluation_timer", "2", "-1"},
			    {"learning_mode_only","y","-1"},
			    {"API_listen_port","5523","-1"},
				{"apply_default_system_tuning","n","-1"}

			   };

void fDoGetUserCfgValues(void)
{
	FILE * userCfgPtr = 0;	
	char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    char *p = 0;
    char setting[256];
	int count = 0;
    time_t clk;
    char ctime_buf[27];
	char *header[] = {"Name", "Default Value", "Configured Value"};
    
    gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"\n%s %s: Opening user provided config file: *%s*\n",ctime_buf, phase2str(current_phase), pUserCfgFile);
	userCfgPtr = fopen(pUserCfgFile,"r");
	if (!userCfgPtr)
	{
		int save_errno = errno;
    	gettime(&clk, ctime_buf);
    	fprintf(tunLogPtr,"\n%s %s: Opening of %s failed, errno = %d\n",ctime_buf, phase2str(current_phase), pUserCfgFile, save_errno);
		return;
		
	}

    while ((nread = getline(&line, &len, userCfgPtr)) != -1) 
	{
		int ind = 0;
		memset(setting,0,sizeof(setting));
        p = line;
		while (!isblank((int)p[ind])) {
				setting[ind] = p[ind];
				ind++;
		}

      	/* compare with known list now */
        for (count = 0; count < NUMUSERVALUES; count++)
        {
            if (strcmp(userValues[count].aUserValues, setting) == 0) //found
            {
				int y = 0;
				memset(setting,0,sizeof(setting));
        		while (isblank((int)p[ind])) //get past blanks etc
						ind++;
					
                setting[y++] = p[ind++];

        		while (isalnum((int)p[ind])) 
				{
                	setting[y++] = p[ind++];
				}
				
				strcpy(userValues[count].cfg_value, setting);
				break;
            }
        }

	}

//#define PAD_MAX	39
#define PAD_MAX	49
#define HEADER_PAD	45
//#define HEADER_PAD	35
#define CONST_PAD	12
    gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: Final user config values after using settings from %s:\n",ctime_buf, phase2str(current_phase), pUserCfgFile);
	fprintf(tunLogPtr,"\n%s %*s %20s\n", header[0], HEADER_PAD, header[1], header[2]);
	for (count = 0; count < NUMUSERVALUES; count++) 
	{	int vPad = PAD_MAX-(strlen(userValues[count].aUserValues));
		//int vPad = PAD_MAX-(strlen(userValues[count].aUserValues) - CONST_PAD);
		fprintf(tunLogPtr,"%s %*s %20s\n",userValues[count].aUserValues, vPad, userValues[count].default_val, userValues[count].cfg_value);
		if (strcmp(userValues[count].aUserValues,"evaluation_timer") == 0)
		{
			int cfg_val = atoi(userValues[count].cfg_value);
			if (cfg_val == -1) //wasn't set properly
				gInterval = atoi(userValues[count].default_val);
			else
				gInterval = cfg_val;
		}
		else
			if (strcmp(userValues[count].aUserValues,"learning_mode_only") == 0)
			{
				if (userValues[count].cfg_value[0] == 'n') 
					gTuningMode = 'y';
			}
			else
				if (strcmp(userValues[count].aUserValues,"apply_default_system_tuning") == 0)
				{
					if (userValues[count].cfg_value[0] == 'y') 
						gApplyDefSysTuning = 'y';
				}
	}

    gettime(&clk, ctime_buf);
	//fprintf(tunLogPtr,"\n%s ***Using 'evaluation_timer' with value %d***\n", ctime_buf, gInterval);
	free(line); //must free
	return;
}

void fDo_lshw(void)
{
	char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    char *p = 0;
    int count = 0, found = 0;
	FILE * lswh_ptr = 0;
	int state = 0;
	char savesize[16];
	char savecap[16];
	char savelinesize[256];
	time_t clk;
    char ctime_buf[27];

	system("sudo lshw > /tmp/lswh_output 2>&1");

	lswh_ptr = fopen("/tmp/lswh_output","r");
	gettime(&clk, ctime_buf);
	if (!lswh_ptr)
	{
    	fprintf(tunLogPtr,"%s %s: Could not open lswh file to check more comparisons.\n", ctime_buf, phase2str(current_phase));
		return;
	}

    while (((nread = getline(&line, &len, lswh_ptr)) != -1) && !found) {
			switch (state) {
				case 0:
	    			if (strstr(line,"*-memory\n"))
	    			{
							gettime(&clk, ctime_buf);
    						fprintf(tunLogPtr,"\n%s %s: The utility 'lshw' reports for memory:\n", ctime_buf, phase2str(current_phase));
							count++;
							state = 1;
					}
					break;

				case 1:
						if ((p = strstr(line,"size: ")))
						{
								state = 2;
								p = p + 6; //sizeof "size: "	
								if (isdigit((int)*p))
								{
									int y = 0;
									memset(savesize,0,sizeof(savesize));
									while (isdigit((int)*p))
									{
										savesize[y] = *p;
										p++;
									}
									strncpy(savelinesize,line, sizeof(savelinesize));
								}
								else
								{
									gettime(&clk, ctime_buf);
    								fprintf(tunLogPtr,"%s %s: memory size in lshw is not niumerical***\n", ctime_buf, phase2str(current_phase));
									free(line);
									return; // has to be a digit
								}
						}
						break;

				case 2:
						if ((p = strstr(line,"capacity: ")))
						{
								state = 3;
								p = p + 10; //sizeof "capacity: "	
								if (isdigit((int)*p))
								{
									int y = 0;
									memset(savecap,0,sizeof(savecap));
									while (isdigit((int)*p))
									{
										savecap[y] = *p;
										p++;
									}
								}
								else
								{
									gettime(&clk, ctime_buf);
    								fprintf(tunLogPtr,"%s %s: memory size in lshw is not numerical***\n", ctime_buf, phase2str(current_phase));
									free(line);
									return; // has to be a digit
								}
									
								gettime(&clk, ctime_buf);

								if (strcmp(savecap,savesize) == 0)
								{
									fprintf(tunLogPtr,"%s %s: maximum memory installed in system\n", ctime_buf, phase2str(current_phase));
									fprintf(tunLogPtr,"%62s",line);
									fprintf(tunLogPtr,"%62s",savelinesize);
								}
								else
								{
									fprintf(tunLogPtr,"%62s",line);
									fprintf(tunLogPtr,"%62s",savelinesize);
									fprintf(tunLogPtr,"%s %s: you could install more memory in the system if you wish...\n", ctime_buf, phase2str(current_phase));
								}
								found = 1;

						}
						break;

				default:
						break;
			}
	}
	
	free(line);
return;
}

/* This works with tuning Module */

#define bbr 		0
#define fq_codel 	1
char *aStringval[] ={"bbr", "fq_codel"};

typedef struct {
    char * setting;
    uint32_t  minimum;
    int xDefault; //if default is -1, then default and max are nops
    uint32_t maximum;
}host_tuning_vals_t;

/* 
 * Suggestion for net.ipv4.tcp_mem...
 *
 * for tcp_mem, set it to twice the maximum value for tcp_[rw]mem multiplied by  * the maximum number of running network applications divided by 4096 bytes per  * page.
 * Increase rmem_max and wmem_max so they are at least as large as the third 
 * values of tcp_rmem and tcp_wmem.
 */
#define TUNING_NUMS	8
/* Must change TUNING_NUMS if adding more to the array below */
#if 0
host_tuning_vals_t aTuningNumsToUse[TUNING_NUMS] = {
    {"net.core.rmem_max",   			67108864,       	-1,      	0},
    {"net.core.wmem_max",   			67108864,       	-1,      	0},
    {"net.ipv4.tcp_rmem",       			4096,       87380,   33554432},
    {"net.ipv4.tcp_wmem",       			4096,       65536,   33554432},
    {"net.ipv4.tcp_mtu_probing",			   1,       	-1,      	0},
    {"net.ipv4.tcp_congestion_control",	    bbr, 			-1, 			0}, //uses #defines to help
    {"net.core.default_qdisc",		    fq_codel, 			-1, 			0}, //uses #defines
    {"MTU",		                               0, 		   84, 			0}
};
#endif
host_tuning_vals_t aTuningNumsToUse[TUNING_NUMS] = {
    {"net.core.rmem_max",   			67108864,       	-1,      	0},
    {"net.core.wmem_max",   			67108864,       	-1,      	0},
    {"net.ipv4.tcp_mtu_probing",			   1,       	-1,      	0},
    {"net.ipv4.tcp_congestion_control",	    bbr, 			-1, 			0}, //uses #defines to help
    {"net.core.default_qdisc",		    fq_codel, 			-1, 			0}, //uses #defines
    {"net.ipv4.tcp_rmem",       			4096,       87380,   33554432},
    {"net.ipv4.tcp_wmem",       			4096,       65536,   33554432},
    {"MTU",		                               0, 		   84, 			0} //Will leave here but using for now
};
void fDoSystemTuning(void)
{

	char *line = NULL;
    size_t len = 0;
    ssize_t nread;
	char *q, *r, *p = 0;
	char setting[256];
	char value[256];
#if 0
	char devMTUdata[256];
#endif
	int count, intvalue, found = 0;
	FILE * tunDefSysCfgPtr = 0;	
	time_t clk;
    char ctime_buf[27];
	char *pFileCurrentConfigSettings = "/tmp/current_config.orig";
	char *header2[] = {"Setting", "Current Value", "Recommended Value", "Applied"};
	char aApplyDefTun[768];

    gettime(&clk, ctime_buf);

	fprintf(tunLogPtr,"\n\n%s %s: ***Start of Default System Tuning***\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"%s %s: ***------------------------------***\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr, "%s %s: Running gdv.sh - Shell script to Get current config settings***\n", ctime_buf, phase2str(current_phase));

    system("sh ./gdv.sh");
#if 0
    gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s Getting current MTU value on system***\n", ctime_buf);
    sprintf(devMTUdata, "echo MTU = `cat /sys/class/net/%s/mtu` >> %s", netDevice, pFileCurrentConfigSettings);
	system(devMTUdata); 
#endif
	tunDefSysCfgPtr = fopen(pFileCurrentConfigSettings,"r");
	if (!tunDefSysCfgPtr)
	{
    	gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: Could not open Tuning Module default current config file, '%s', exiting...\n", ctime_buf, phase2str(current_phase), pFileCurrentConfigSettings);
		fclose(tunLogPtr);
		exit(-2);
	}

    gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: Tuning Module default current configuration file, '%s', opened***\n", ctime_buf, phase2str(current_phase), pFileCurrentConfigSettings);
	fprintf(tunLogPtr, "%s %s: ***NOTE - Some settings have a minimum, default and maximum values, while others only have a single value***\n\n", ctime_buf, phase2str(current_phase));

#define SETTINGS_PAD_MAX 58
#define HEADER_SETTINGS_PAD  50
//#define CONST_PAD   12
    //fprintf(tunLogPtr,"\n%s %*s %20s\n", header[0], HEADER_PAD, header[1], header[2]);
	fprintf(tunLogPtr, "%s %*s %25s %20s\n", header2[0], HEADER_SETTINGS_PAD, header2[1], header2[2], header2[3]);
	fflush(tunLogPtr);

    while ((nread = getline(&line, &len, tunDefSysCfgPtr)) != -1) {
    	//printf("Retrieved line of length %zu:\n", nread);
		//printf("&%s&",line);
		memset(setting,0,256);
		p = line;
		q = strchr(line,' '); //search for space	
		len = (q-p) + 1;
		strncpy(setting,p,len);
		if (setting[len-1] == ' ')
			setting[--len] = 0;
		else
			setting[len] = 0;

		fprintf(tunLogPtr,"%s",setting);
		//fprintf(tunLogPtr,"\nsetting is ***%s***\n",setting);
		/* compare with known list now */
		for (count = 0; count < TUNING_NUMS; count++)
		{
			memset(value,0,256);
			if (strcmp(aTuningNumsToUse[count].setting, setting) == 0) //found
			{
				int vPad = SETTINGS_PAD_MAX-(strlen(setting));
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
					if(intvalue <= aTuningNumsToUse[count].minimum)
					{
						if (aTuningNumsToUse[count].xDefault == -1) //only one value
						{
							//fprintf(tunLogPtr,"Current config value for *%s* is *%s* which is less than the minimum recommendation...\n",setting, value);	
							//fprintf(tunLogPtr,"You should change to the recommended setting of *%d* for *%s*.\n",aTuningNumsToUse[count].minimum, setting);
							fprintf(tunLogPtr,"%*s", vPad, value);	
							fprintf(tunLogPtr,"%26d %20c\n",aTuningNumsToUse[count].minimum, gApplyDefSysTuning);
							
							if (gApplyDefSysTuning == 'y')
							{
								//Apply Inital DefSys Tuning
								sprintf(aApplyDefTun,"sysctl -w %s=%d",setting,aTuningNumsToUse[count].minimum);
								printf("%s\n",aApplyDefTun);	
								//system(aApplyDefTun);
							}
						}
						else
							{//has min, default and max values - get them...
								//fprintf(tunLogPtr,"Current config value for *%s* is *%s*...\n",setting, value);	
								//fprintf(tunLogPtr,"You should change to the recommended setting of *%s* to *%d\t%d\t%d*.\n",setting, aTuningNumsToUse[count].minimum, aTuningNumsToUse[count].xDefault, aTuningNumsToUse[count].maximum);
								//Let's parse the value stringand get the min, etc. separaately
								int i, j;
								char min[256];
								char def[256];
								char max[256];
								memset(min,0,256);
								memset(def,0,256);
								memset(max,0,256);
								i = 0;
								while (isdigit(value[i]))
								{
									min[i] = value[i];
									i++;
								}

								while(!isdigit(value[i]))
									i++;
							
								j = 0;
								while (isdigit(value[i]))
								{
									def[j] = value[i];
									i++;
									j++;
								}
								
								while(!isdigit(value[i]))
									i++;

								j = 0;
								while (isdigit(value[i]))
								{
									max[j] = value[i];
									i++;
									j++;
								}
#define SETTINGS_PAD_MAX2 43
								vPad = SETTINGS_PAD_MAX2-(strlen(min) + strlen(def) + strlen(max));
								fprintf(tunLogPtr,"%*s %s %s", vPad, min, def, max);	
#define SETTINGS_PAD_MAX3 28
								{
									char strValmin[128];
									char strValdef[128];
									char strValmax[128];
									int total;
									int y = sprintf(strValmin,"%d",aTuningNumsToUse[count].minimum);
									total = y;
									y = sprintf(strValdef,"%d",aTuningNumsToUse[count].xDefault);
									total += y;
									y = sprintf(strValmax,"%d",aTuningNumsToUse[count].maximum);
									total += y;
									vPad = SETTINGS_PAD_MAX3-total;
									//fprintf(tunLogPtr,"%11d %d %d %20c y = %d\n", aTuningNumsToUse[count].minimum, aTuningNumsToUse[count].xDefault, aTuningNumsToUse[count].maximum, gApplyDefSysTuning,total);
									fprintf(tunLogPtr,"%*s %s %s %20c\n", vPad, strValmin, strValdef, strValmax, gApplyDefSysTuning);
									if (gApplyDefSysTuning == 'y')
									{
										//Apply Inital DefSys Tuning
										sprintf(aApplyDefTun,"sysctl -w %s=%s %s %s",setting, strValmin, strValdef, strValmax);
										printf("%s\n",aApplyDefTun);	
										//system(aApplyDefTun);
									}
								}
							//	printf("*value = *%s*, min=***%s***, def=***%s***, max=***%s***\n", value, min, def, max);	
								
							}
					}
					else //Leaving out this case for now
						if (strcmp(aTuningNumsToUse[count].setting, "MTU") == 0) //special case - will have to fix up - not using currently
						{
							aTuningNumsToUse[count].xDefault = intvalue;
							//fprintf(tunLogPtr,"Current config value for *%s* is *%s*...\n",setting, value);	
							fprintf(tunLogPtr,"%*s%26s %20c\n",vPad, value, "-", '-');	
						}
					
				}	
				else
					{ //must be a string
						if (strcmp(value, aStringval[aTuningNumsToUse[count].minimum]) != 0)
						{
							//fprintf(tunLogPtr,"Current config value for *%s* is *%s* which is not the same as the recommendation...\n",setting, value);	
							//fprintf(tunLogPtr,"You should change to the recommended setting of *%s* for *%s*.\n",aStringval[aTuningNumsToUse[count].minimum], setting);
							fprintf(tunLogPtr,"%*s", vPad, value);	
							fprintf(tunLogPtr,"%26s %20c\n",aStringval[aTuningNumsToUse[count].minimum], gApplyDefSysTuning);
							if (gApplyDefSysTuning == 'y')
							{
								//Apply Inital DefSys Tuning
								sprintf(aApplyDefTun,"sysctl -w %s=%s",setting,aStringval[aTuningNumsToUse[count].minimum]);
								printf("%s\n",aApplyDefTun);	
								//system(aApplyDefTun);
							}
						}
						else
							{
								//fprintf(tunLogPtr,"Current config value for *%s* is *%s* is the same as the recommendation...\n",setting, value);	
								//fprintf(tunLogPtr,"%*s %25s %20c\n", vPad, value, aStringval[aTuningNumsToUse[count].minimum], gApplyDefSysTuning);	
								fprintf(tunLogPtr,"%*s %25s %20s\n", vPad, value, aStringval[aTuningNumsToUse[count].minimum], "na");	
								if (gApplyDefSysTuning == 'y')
								{
									//Apply Inital Def
									//No need to apply - already set...
									sprintf(aApplyDefTun,"no need to apply for %s=%s since already set...",setting, aStringval[aTuningNumsToUse[count].minimum]);
									printf("%s\n",aApplyDefTun);	
									//system(aApplyDefTun);
								}
							}
							
					}

				found = 1;
				break;
			}
		}

		if (!found)
		{
    		gettime(&clk, ctime_buf);
			fprintf(tunLogPtr,"%s %s: ERR*** Could not find the following setting **%s**\n", ctime_buf, phase2str(current_phase), setting);
		}
		
	}

	/* find additional things that could be tuned */
	fDo_lshw();

    gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"\n%s %s: ***For additional info about your hardware settings and capabilities, please run \n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"%s %s: ***'sudo dmidecore' and/or 'sudo lshw'. \n\n", ctime_buf, phase2str(current_phase));

	fprintf(tunLogPtr, "\n%s %s: ***Closing Tuning Module default system configuration file***\n", ctime_buf, phase2str(current_phase));
	fclose(tunDefSysCfgPtr);

    gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"\n%s %s: ***End of Default System Tuning***\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"%s %s: ***----------------------------***\n\n", ctime_buf, phase2str(current_phase));

	free(line);
	return;
}

void * fTalkToKernel(void * vargp)
{
	int result = 0;
	char aMessage[512];
	int * fd = (int *) vargp;
	time_t clk;
    char ctime_buf[27];


	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting communication with kernel module...***\n", ctime_buf, phase2str(current_phase));
	//catch_sigint();
	while(1) 
	{	
		strcpy(aMessage,"This is a message...");

		result = write(*fd,aMessage,strlen(aMessage));
		gettime(&clk, ctime_buf);
		if (result < 0)
			fprintf(tunLogPtr,"%s %s: There was an error writing***\n", ctime_buf, phase2str(current_phase));
		else
			fprintf(tunLogPtr,"%s %s: ***message written to kernel module = ***%s***\n", ctime_buf, phase2str(current_phase), aMessage);

		memset(aMessage,0,512);
		result = read(*fd,aMessage,512);
		gettime(&clk, ctime_buf);

		if (result < 0)
			fprintf(tunLogPtr,"%s %s: There was an error readin***\n", ctime_buf, phase2str(current_phase));
		else
			fprintf(tunLogPtr,"%s %s: ***message read from kernel module = ***%s***\n", ctime_buf, phase2str(current_phase), aMessage);

		fflush(tunLogPtr);
		sleep(gInterval);
	}
}


int main(int argc, char **argv) 
{

	char *pDevName = "/dev/tuningMod";
	int fd; 
	int vRetFromKernelThread, vRetFromKernelJoin;
	int vRetFromRunBpfThread, vRetFromRunBpfJoin;
	pthread_t talkToKernelThread_id, doRunBpfCollectionThread_id;
	sArgv_t sArgv;
	time_t clk;
	char ctime_buf[27];

	sArgv.argc = argc;
	sArgv.argv = argv;
	
	catch_sigint();
	tunLogPtr = fopen("/tmp/tuningLog","w");
	if (!tunLogPtr)
	{
		printf("Could not open tuning Logfile, exiting...\n");
		exit(-1);
	}

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: tuning Log opened***\n", ctime_buf, phase2str(current_phase));

	if (argc == 3)
		strcpy(netDevice,argv[2]);
	else
		{
			gettime(&clk, ctime_buf);
			fprintf(tunLogPtr, "%s %s: Device name not supplied, exiting***\n", ctime_buf, phase2str(current_phase));
			exit(-3);
		}
		

	gettime(&clk, ctime_buf);
	current_phase = ASSESSMENT;

	fDoGetUserCfgValues();

	fDoSystemTuning();

	gettime(&clk, ctime_buf);
	//fprintf(tunLogPtr, "%s ***Changing WorkFlow Phase***\n", ctime_buf);
	current_phase = LEARNING;
	//fprintf(tunLogPtr, "%s WorkFlow Current Phase is %s***\n", ctime_buf, phase2str(current_phase));
	
	fd = open(pDevName, O_RDWR,0);

	if (fd > 0)
	{
		vRetFromKernelThread = pthread_create(&talkToKernelThread_id, NULL, fTalkToKernel, &fd);
	}
	else
	{
		int save_errno = errno;
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Error opening kernel device, errno = %dn***\n",ctime_buf, phase2str(current_phase), save_errno);
		fprintf(tunLogPtr, "%s %s: Closing tuning Log and exiting***\n", ctime_buf, phase2str(current_phase));
		fclose(tunLogPtr);
		exit(-8);
	}
			
	fflush(tunLogPtr);

	vRetFromRunBpfThread = pthread_create(&doRunBpfCollectionThread_id, NULL, fDoRunBpfCollection, &sArgv);;

	if (vRetFromKernelThread == 0)
    	vRetFromKernelJoin = pthread_join(talkToKernelThread_id, NULL);

	if (vRetFromRunBpfThread == 0)
    	vRetFromRunBpfJoin = pthread_join(doRunBpfCollectionThread_id, NULL);

	if (fd > 0)
		close(fd);

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: Closing tuning Log***\n", ctime_buf, phase2str(current_phase));
	fclose(tunLogPtr);

return 0;
}

