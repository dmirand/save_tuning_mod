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

/******HTTP server *****/
#include "fio.h"
#include "http.h"
void initialize_http_service(void);
/**********************/

#define WORKFLOW_NAMES_MAX	4
#define USING_PERF_EVENT_ARRAY 1
#define TEST 1
static char *testNetDevice = "enp6s0np0";

static void gettime(time_t *clk, char *ctime_buf) 
{
	*clk = time(NULL);
	ctime_r(clk,ctime_buf);
	ctime_buf[24] = ':';
}

/* msleep(): Sleep for the requested number of milliseconds. */
int msleep(long msec)
{
	struct timespec ts;
	int res;

	if (msec < 0)
	{
		errno = EINVAL;
		return -1;
	}

	ts.tv_sec = msec / 1000;
	ts.tv_nsec = (msec % 1000) * 1000000;

	do {
		res = nanosleep(&ts, &ts);
	} while (res && errno == EINTR);

	return res;
}

FILE * tunLogPtr = 0;
void fDoGetUserCfgValues(void);
void fDoBiosTuning(void);
void fDoNicTuning(void);
void fDoSystemtuning(void);
void fDo_lshw(void);
static char *pUserCfgFile = "user_config.txt";
static int gInterval = 2; //default in seconds
static int gAPI_listen_port = 5523; //default listening port
static char gTuningMode = 0;
static char gApplyBiosTuning = 'n';
static char gApplyNicTuning = 'n';
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
#include "../libbpf/src/libbpf.h"
/* Lesson#1: this prog does not need to #include <bpf/libbpf.h> as it only uses
 * the simple bpf-syscall wrappers, defined in libbpf #include<bpf/bpf.h>
 */

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_kern_user.h"
#include "bpf_util.h" /* bpf_num_possible_cpus */

#ifdef USING_PERF_EVENT_ARRAY
void read_buffer_sample_perf(void *ctx, int cpu, void *data, unsigned int len) 
{
	time_t clk;
	char ctime_buf[27];
	struct int_telemetry *evt = (struct int_telemetry *)data;
	int	 do_something;

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: %s::: \n", ctime_buf, phase2str(current_phase), "MetaData from Collector Module:");
	fprintf(tunLogPtr,"%s %s: ::: switch %d egress port %d ingress port %d ingress time %d egress time %d queue id %d queue_occupancy %d\n", ctime_buf, phase2str(current_phase), evt->switch_id, evt->egress_port_id, evt->ingress_port_id, evt->ingress_time, evt->egress_time, evt->queue_id, evt->queue_occupancy);

	//Process network state received from Collector
	//Make suggestions and or apply if authorized by the DTN operator
	//
	//Also, look at INT Queue Occupancy and Hop Delay to estimate 
	//bottlenecks in the path. Tuning will be suggested based on these
	//premises. 
	//
	if (gTuningMode)
	{
		//DTN operator has authorized the app to apply the suggestions.
		//make it so. 
		//
		do_something = 1;
	}

	return;
}
#else
static int read_buffer_sample(void *ctx, void *data, size_t len) 
{
	time_t clk;
	char ctime_buf[27];
	struct int_telemetry *evt = (struct int_telemetry *)data;
	int	 do_something;

	gettime(&clk, ctime_buf);
  	fprintf(tunLogPtr,"%s %s: %s::: \n", ctime_buf, phase2str(current_phase), "MetaData from Collector Module:");
	fprintf(tunLogPtr,"%s %s: ::: switch %d egress port %d ingress port %d ingress time %d egress time %d queue id %d queue_occupancy %d\n", ctime_buf, phase2str(current_phase), evt->switch_id, evt->egress_port_id, evt->ingress_port_id, evt->ingress_time, evt->egress_time, evt->queue_id, evt->queue_occupancy);

	//Process network state received from Collector
	//Make suggestions and or apply if authorized by the DTN operator
	//
	//Also, look at INT Queue Occupancy and Hop Delay to estimate 
	//bottlenecks in the path. Tuning will be suggested based on these
	//premises. 
	//
	if (gTuningMode)
	{
		//DTN operator has authorized the app to apply the suggestions.
		//make it so. 
		//
		do_something = 1;
	}

	return 0;
}
#endif

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

#ifdef USING_PERF_EVENT_ARRAY
void * fDoRunBpfCollectionPerfEventArray(void * vargp) 
{

	struct bpf_map_info info = { 0 };
	char pin_dir[PATH_MAX];
	int buffer_map_fd;
	struct perf_buffer *pb = NULL;
	struct perf_buffer_opts pb_opts = {};
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
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ERR: required option --dev missing\n\n", ctime_buf, phase2str(current_phase));
		usage(sArgv->argv[0], __doc__, long_options, (sArgv->argc == 1));
		fflush(tunLogPtr);
		return (void *)1;
		//return EXIT_FAIL_OPTION;
	}

	/* Use the --dev name as subdir for finding pinned maps */
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ERR: creating pin dirname\n", ctime_buf, phase2str(current_phase));
		fflush(tunLogPtr);
		return (void *)2;
		//return EXIT_FAIL_OPTION;
	}

	buffer_map_fd = open_bpf_map_file(pin_dir, "int_ring_buffer", &info);
	if (buffer_map_fd < 0) {
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ERR: fail to get buffer map fd\n", ctime_buf, phase2str(current_phase));
		fflush(tunLogPtr);
		return (void *)3;
		//return EXIT_FAIL_BPF;
	}

	if (verbose) {
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"\n%s %s: Collecting stats from BPF map\n", ctime_buf, phase2str(current_phase));
		fprintf(tunLogPtr,"%s %s: - BPF map (bpf_map_type:%d) id:%d name:%s"
			" max_entries:%d\n", ctime_buf, phase2str(current_phase),
		info.type, info.id, info.name, info.max_entries
			);
	}

	pb_opts.sample_cb = read_buffer_sample_perf;
	pb = perf_buffer__new(buffer_map_fd, 4 /* 16KB per CPU */, &pb_opts);
	if (libbpf_get_error(pb)) {
		err = -1;
		gettime(&clk, ctime_buf);
		fprintf (tunLogPtr,"%s %s: can't create ring buffer struct****\n", ctime_buf, phase2str(current_phase));
		fflush(tunLogPtr);
		goto cleanup;
	}


	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: Starting communication with Collector Module...***\n", ctime_buf, phase2str(current_phase));

	if (gTuningMode) 
		current_phase = TUNING;

	while (1) 
	{
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		//sleep(gInterval);
	}

cleanup:
	perf_buffer__free(pb);
	return (void *)7;
}
#else
void * fDoRunBpfCollectionRingBuf(void * vargp) 
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
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ERR: required option --dev missing\n\n", ctime_buf, phase2str(current_phase));
		usage(sArgv->argv[0], __doc__, long_options, (sArgv->argc == 1));
		fflush(tunLogPtr);
		return (void *)1;
		//return EXIT_FAIL_OPTION;
	}

	/* Use the --dev name as subdir for finding pinned maps */
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ERR: creating pin dirname\n", ctime_buf, phase2str(current_phase));
		fflush(tunLogPtr);
		return (void *)2;
		//return EXIT_FAIL_OPTION;
	}

	buffer_map_fd = open_bpf_map_file(pin_dir, "int_ring_buffer", &info);
	if (buffer_map_fd < 0) {
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ERR: fail to get buffer map fd\n", ctime_buf, phase2str(current_phase));
		fflush(tunLogPtr);
		return (void *)3;
		//return EXIT_FAIL_BPF;
	}

	/* check map info, e.g. datarec is expected size */
	map_expect.max_entries = 16384;
	err = check_map_fd_info(&info, &map_expect);
	if (err) {
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ERR: map via FD not compatible\n", ctime_buf, phase2str(current_phase));
		fflush(tunLogPtr);
		return (void *)4;
	}

	if (verbose) {
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"\n%s %s: Collecting stats from BPF map\n", ctime_buf, phase2str(current_phase));
		fprintf(tunLogPtr,"%s %s: - BPF map (bpf_map_type:%d) id:%d name:%s"
			" max_entries:%d\n", ctime_buf, phase2str(current_phase),
			info.type, info.id, info.name, info.max_entries
			);
	}

	rb = ring_buffer__new(buffer_map_fd, read_buffer_sample, NULL, NULL);

	if (!rb)
	{
		gettime(&clk, ctime_buf);
		fprintf (tunLogPtr,"%s %s: can't create ring buffer struct****\n", ctime_buf, phase2str(current_phase));
		fflush(tunLogPtr);
		return (void *)6;
	}

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: Starting communication with Collector Module...***\n", ctime_buf, phase2str(current_phase));

	if (gTuningMode) 
		current_phase = TUNING;

	while (1) 
	{
		ring_buffer__consume(rb);
		sleep(gInterval);
	}
    	
	return (void *)7;
}
#endif

/* End of bpf stuff ****/

/* Must change NUMUSERVALUES below if adding more values */
#define NUMUSERVALUES	6
#define USERVALUEMAXLENGTH	256
typedef struct {
	char aUserValues[USERVALUEMAXLENGTH];
	char default_val[32];
	char cfg_value[32];
} sUserValues_t[NUMUSERVALUES];

sUserValues_t userValues = {{"evaluation_timer", "2", "-1"},
			    {"learning_mode_only","y","-1"},
			    {"API_listen_port","5523","-1"},
			    {"apply_default_system_tuning","n","-1"},
			    {"apply_bios_tuning","n","-1"},
			    {"apply_nic_tuning","n","-1"}
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
		while (!isblank((int)p[ind])) 
		{
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

#define PAD_MAX	49
#define HEADER_PAD	45
#define CONST_PAD	12
	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: Final user config values after using settings from %s:\n",ctime_buf, phase2str(current_phase), pUserCfgFile);
	fprintf(tunLogPtr,"%s %s: A configured value of -1 means the setting was not configured and the default value will be used.\n",ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"\n%s %*s %20s\n", header[0], HEADER_PAD, header[1], header[2]);
	for (count = 0; count < NUMUSERVALUES; count++) 
	{
		int vPad = PAD_MAX-(strlen(userValues[count].aUserValues));
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
					gTuningMode = 1;
			}
			else
				if (strcmp(userValues[count].aUserValues,"apply_default_system_tuning") == 0)
				{
					if (userValues[count].cfg_value[0] == 'y') 
						gApplyDefSysTuning = 'y';
				}
				else
					if (strcmp(userValues[count].aUserValues,"apply_bios_tuning") == 0)
					{
						if (userValues[count].cfg_value[0] == 'y') 
							gApplyBiosTuning = 'y';
					}
					else
						if (strcmp(userValues[count].aUserValues,"apply_nic_tuning") == 0)
						{
							if (userValues[count].cfg_value[0] == 'y') 
								gApplyNicTuning = 'y';
						}
						else
							if (strcmp(userValues[count].aUserValues,"API_listen_port") == 0)
							{
								int cfg_val = atoi(userValues[count].cfg_value);
								if (cfg_val == -1) //wasn't set properly
									gAPI_listen_port = atoi(userValues[count].default_val);
								else
									gAPI_listen_port = cfg_val;
							}
	}

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"\n%s %s: ***Note: Using 'evaluation_timer' with value %d seconds***\n", ctime_buf, phase2str(current_phase), gInterval);
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

	while (((nread = getline(&line, &len, lswh_ptr)) != -1) && !found) 
	{
		switch (state)	{
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
    							fprintf(tunLogPtr,"%s %s: memory size in lshw is not numerical***\n", ctime_buf, phase2str(current_phase));
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

#define bbr		0
#define fq		1
#define htcp		2
#define reno		3
#define cubic		4
#define getvalue	5
char *aStringval[] ={"bbr", "fq", "htcp", "reno", "cubic", "getvalue"};

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
 *
 * A minimum value of "getvalue" means that I'm just interested in the value.
 */
#define NUM_SYSTEM_SETTINGS 100
#define MAX_SIZE_SYSTEM_SETTING_STRING  768
int aApplyDefTunCount = 0;
char aApplyDefTun2DArray[NUM_SYSTEM_SETTINGS][MAX_SIZE_SYSTEM_SETTING_STRING];

#define TUNING_NUMS	9
/* Must change TUNING_NUMS if adding more to the array below */
host_tuning_vals_t aTuningNumsToUse[TUNING_NUMS] = {
	{"net.core.rmem_max",  				67108864,		-1,		0},
	{"net.core.wmem_max",  				67108864,		-1,		0},
	{"net.ipv4.tcp_mtu_probing",			       1,		-1,		0},
	{"net.ipv4.tcp_available_congestion_control",	getvalue,		-1,		0},
	{"net.ipv4.tcp_congestion_control",		    htcp,		-1,		0}, //uses #defines to help
	{"net.core.default_qdisc",			      fq,		-1,		0}, //uses #defines
	{"net.ipv4.tcp_rmem",				    4096,	     87380,	 33554432},
	{"net.ipv4.tcp_wmem",				    4096,	     65536,	 33554432},
	{"MTU",						       0,		84,		0} //Will leave here but not using for now
};
void fDoSystemTuning(void)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	char *q, *r, *p = 0;
	char setting[256];
	char value[256];
	int congestion_control_recommended_avail = 0;
#if 0
	char devMTUdata[256];
#endif
	int count, intvalue, found = 0;
	FILE * tunDefSysCfgPtr = 0;	
	time_t clk;
	char ctime_buf[27];
	char *pFileCurrentConfigSettings = "/tmp/current_config.orig";
	char *header2[] = {"Setting", "Current Value", "Recommended Value", "Applied"};
	char aApplyDefTun[MAX_SIZE_SYSTEM_SETTING_STRING];

	gettime(&clk, ctime_buf);

	fprintf(tunLogPtr,"\n\n%s %s: -------------------------------------------------------------------\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,  "%s %s: ******************Start of Default System Tuning*******************\n", ctime_buf, phase2str(current_phase));
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
	fprintf(tunLogPtr, "%s %s: ***NOTE - Some settings have a minimum, default and maximum values, while others only have a single value***\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr, "%s %s: ***NOTE - If the recommended value is less than or equal to the current value, no changes will be made for that setting***\n\n", ctime_buf, phase2str(current_phase));

#define SETTINGS_PAD_MAX 58
#define HEADER_SETTINGS_PAD  50
	fprintf(tunLogPtr, "%s %*s %25s %20s\n", header2[0], HEADER_SETTINGS_PAD, header2[1], header2[2], header2[3]);
	fflush(tunLogPtr);

	while ((nread = getline(&line, &len, tunDefSysCfgPtr)) != -1) 
	{
		memset(setting,0,256);
		p = line;
		q = strchr(line,' '); //search for space	
		len = (q-p) + 1;
		strncpy(setting,p,len);
		if (setting[len-1] == ' ')
			setting[--len] = 0;
		else
			setting[len] = 0;

		if (strcmp(setting, "net.ipv4.tcp_available_congestion_control") != 0) //print in this case
			fprintf(tunLogPtr,"%s",setting);

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
							fprintf(tunLogPtr,"%*s", vPad, value);	
							if (intvalue == aTuningNumsToUse[count].minimum)
								fprintf(tunLogPtr,"%26d %20s\n",aTuningNumsToUse[count].minimum, "na");
							else
								{
									fprintf(tunLogPtr,"%26d %20c\n",aTuningNumsToUse[count].minimum, gApplyDefSysTuning);
							
									if (gApplyDefSysTuning == 'y')
									{
										//Apply Inital DefSys Tuning
										sprintf(aApplyDefTun,"sysctl -w %s=%d",setting,aTuningNumsToUse[count].minimum);
										system(aApplyDefTun);
									}
									else
										{
											//Save in Case Operator want to apply from menu
											sprintf(aApplyDefTun,"sysctl -w %s=%d",setting,aTuningNumsToUse[count].minimum);
											memcpy(aApplyDefTun2DArray[aApplyDefTunCount], aApplyDefTun, strlen(aApplyDefTun));
											aApplyDefTunCount++;
										}
								}
						}
						else
							{
								//has min, default and max values - get them...
								//Let's parse the value string and get the min, etc. separately
								int i, j, currmax;
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
								currmax = atoi(max);
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
									if (aTuningNumsToUse[count].maximum > currmax)
									{
										fprintf(tunLogPtr,"%*s %s %s %20c\n", vPad, strValmin, strValdef, strValmax, gApplyDefSysTuning);
										if (gApplyDefSysTuning == 'y')
										{
											//Apply Inital DefSys Tuning
											sprintf(aApplyDefTun,"sysctl -w %s=\"%s %s %s\"",setting, strValmin, strValdef, strValmax);
											system(aApplyDefTun);
										}
										else
											{
												//Save in Case Operator want to apply from menu
                                            							sprintf(aApplyDefTun,"sysctl -w %s=\"%s %s %s\"",setting, strValmin, strValdef, strValmax);
                                            							memcpy(aApplyDefTun2DArray[aApplyDefTunCount], aApplyDefTun, strlen(aApplyDefTun));
                                            							aApplyDefTunCount++;
 											}
									}
									else
										fprintf(tunLogPtr,"%*s %s %s %20s\n", vPad, strValmin, strValdef, strValmax, "na");
								}
							}
					}
					else
						{ //intvalue > aTuningNumsToUse[count].minimum
							if (aTuningNumsToUse[count].xDefault == -1) //only one value
							{
								fprintf(tunLogPtr,"%*s", vPad, value);
								fprintf(tunLogPtr,"%26d %20s\n",aTuningNumsToUse[count].minimum, "na");
							}
							else
								{
									//has min, default and max values - get them...
									//Let's parse the value string and get the min, etc. separately
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

										fprintf(tunLogPtr,"%*s %s %s %20s\n", vPad, strValmin, strValdef, strValmax, "na");
									}
								}
						}
#if 0
						else //Leaving out this case for now
							if (strcmp(aTuningNumsToUse[count].setting, "MTU") == 0) //special case - will have to fix up - not using currently
							{
								aTuningNumsToUse[count].xDefault = intvalue;
								fprintf(tunLogPtr,"%*s%26s %20c\n",vPad, value, "-", '-');	
							}
#endif
				}	
				else
					{ //must be a string
						if (strcmp(value, aStringval[aTuningNumsToUse[count].minimum]) != 0)
						{
#if 1
							if (strcmp(setting, "net.ipv4.tcp_available_congestion_control") == 0)
							{
								if (strstr(value,"htcp"))
									congestion_control_recommended_avail = 1;

								break;
							}
#endif
							fprintf(tunLogPtr,"%*s", vPad, value);	

							if (strcmp(setting, "net.ipv4.tcp_congestion_control") == 0)
							{
								if (!congestion_control_recommended_avail)
								{ 
									//try modprobe
									char modprobe_str[64];
									char *line2 = NULL;
									size_t len2 = 0;
									ssize_t nread2;
									FILE * modprobeFilePtr = 0;

									sprintf(modprobe_str,"%s","modprobe tcp_htcp > /tmp/modprobe_result 2>&1");
									system(modprobe_str);

									modprobeFilePtr = fopen("/tmp/modprobe_result", "r");
									if (!modprobeFilePtr)
									{
										int save_errno = errno;
										gettime(&clk, ctime_buf);
										fprintf(tunLogPtr,"\n%s %s: Opening of %s failed, errno = %d\n",ctime_buf, phase2str(current_phase), "/tmp/modprobe_result", save_errno);
										fprintf(tunLogPtr,"%s %s: ***Could not determine what value to set net.ipv4.tcp_congestion_control", ctime_buf, phase2str(current_phase));
										break;
									}

									nread2 = getline(&line2, &len2, modprobeFilePtr);
									fclose(modprobeFilePtr);
                                    					system("rm -f /tmp/modprobe_result");

									if (nread2 != -1)
									{
										fprintf(tunLogPtr,"%26s %20s\n",aStringval[aTuningNumsToUse[count].minimum], "*htcp na");
										break; //skip
									}

								}
							}

							fprintf(tunLogPtr,"%26s %20c\n",aStringval[aTuningNumsToUse[count].minimum], gApplyDefSysTuning);
							if (gApplyDefSysTuning == 'y')
							{
								//Apply Inital DefSys Tuning
								sprintf(aApplyDefTun,"sysctl -w %s=%s",setting,aStringval[aTuningNumsToUse[count].minimum]);
								system(aApplyDefTun);
							}
							else
								{
									//Save in Case Operator want to apply from menu
									sprintf(aApplyDefTun,"sysctl -w %s=%s",setting,aStringval[aTuningNumsToUse[count].minimum]);
									memcpy(aApplyDefTun2DArray[aApplyDefTunCount], aApplyDefTun, strlen(aApplyDefTun));
									aApplyDefTunCount++;
								}
						}
						else
							{
								fprintf(tunLogPtr,"%*s %25s %20s\n", vPad, value, aStringval[aTuningNumsToUse[count].minimum], "na");	
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

#if 0
	/* find additional things that could be tuned */
	fDo_lshw();

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"\n%s %s: ***For additional info about your hardware settings and capabilities, please run \n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"%s %s: ***'sudo dmidecode' and/or 'sudo lshw'. \n\n", ctime_buf, phase2str(current_phase));
#endif

	fprintf(tunLogPtr, "\n%s %s: ***Closing Tuning Module default system configuration file***\n", ctime_buf, phase2str(current_phase));
	fclose(tunDefSysCfgPtr);

	{
		char rem_file[512];
		sprintf(rem_file,"rm -f %s", pFileCurrentConfigSettings);
		system(rem_file);
	}

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,  "%s %s: ********************End of Default System Tuning*******************\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,  "%s %s: -------------------------------------------------------------------\n\n", ctime_buf, phase2str(current_phase));

	free(line);
	return;
}

void fDoBiosTuning(void)
{
	char ctime_buf[27];
	time_t clk;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	char aBiosSetting[256];
	char sCPUMAXValue[256];
	char sCPUCURRValue[256];
	int vPad;
	FILE *biosCfgFPtr = 0;
	char *header2[] = {"Setting", "Current Value", "Recommended Value", "Applied"};

	gettime(&clk, ctime_buf);

	fprintf(tunLogPtr,"\n%s %s: -------------------------------------------------------------------\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,  "%s %s: ***************Start of Evaluate BIOS configuration****************\n\n", ctime_buf, phase2str(current_phase));
	
	fprintf(tunLogPtr, "%s %*s %25s %20s\n", header2[0], HEADER_SETTINGS_PAD, header2[1], header2[2], header2[3]);
	fflush(tunLogPtr);

	sprintf(aBiosSetting,"lscpu | grep -E '^CPU MHz|^CPU max MHz' > /tmp/BIOS.cfgfile");
	system(aBiosSetting);

	biosCfgFPtr = fopen("/tmp/BIOS.cfgfile","r");
	if (!biosCfgFPtr)
	{
		int save_errno = errno;
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: Could not open file /tmp/BIOS.cfgfile to work out CPU speed, errno = %d...\n", ctime_buf, phase2str(current_phase), save_errno);
	}
	else
		{
			double cfg_max_val = 0.0;
			double cfg_cur_val = 0.0;

			while((nread = getline(&line, &len, biosCfgFPtr)) != -1) 
			{ //getting CPU speed
				int count = 0, ncount = 0;
		
				if (strstr(line,"CPU MHz:"))
				{
					char *q = line + strlen("CPU MHz:");

					while (!isdigit(q[count])) count++;

					while (isdigit(q[count]) || q[count] == '.')
					{
						sCPUCURRValue[ncount] = q[count];
						ncount++;
						count++;
					}

					sCPUCURRValue[ncount] = 0;
				}
				else
					if (strstr(line,"CPU max MHz:"))
					{
						char *q = line + strlen("CPU max MHz:");
					
						while (!isdigit(q[count])) count++;

						while (isdigit(q[count]) || q[count] == '.')
						{
							sCPUMAXValue[ncount] = q[count];
							ncount++;
							count++;
						}

						sCPUMAXValue[ncount] = 0;
					}
			}
	                    
			cfg_max_val = atof(sCPUMAXValue);
			cfg_cur_val = atof(sCPUCURRValue);

			vPad = SETTINGS_PAD_MAX-(strlen("CPU MHz"));
			fprintf(tunLogPtr,"%s", "CPU MHz"); //redundancy for visual
			fprintf(tunLogPtr,"%*s", vPad, sCPUCURRValue);

			if (cfg_max_val > cfg_cur_val)
			{
				fprintf(tunLogPtr,"%26s %20c\n", sCPUMAXValue, gApplyBiosTuning); //could use %26.4f, cfg_max_val instead
				if (gApplyBiosTuning == 'y')
				{
					//Apply Bios Tuning
					sprintf(aBiosSetting,"cpupower frequency-set --governor performance");
					printf("%s\n",aBiosSetting);
					//system(aBiosSetting);
				}
			}
			else
				fprintf(tunLogPtr,"%26s %20s\n", sCPUMAXValue, "na");

			fclose(biosCfgFPtr);
			system("rm -f /tmp/BIOS.cfgfile"); //cleanup
		}

	/* find additional things that could be tuned */
	fDo_lshw();

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"\n%s %s: ***For additional info about your hardware settings and capabilities, please run \n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"%s %s: ***'sudo dmidecode' and/or 'sudo lshw'. \n", ctime_buf, phase2str(current_phase));

	fprintf(tunLogPtr,"\n%s %s: ****************End of Evaluate BIOS configuration*****************\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,  "%s %s: -------------------------------------------------------------------\n\n", ctime_buf, phase2str(current_phase));

	if (line)
		free(line);

	return;
}

static int rec_txqueuelen = 20000; //receommended value for now
void fDoNicTuning(void)
{
	char ctime_buf[27];
	time_t clk;
	char *line = NULL;
	size_t len = 0;
   	ssize_t nread;
	char aNicSetting[256];
	char sRXMAXValue[256];
	char sRXCURRValue[256];
	char sTXMAXValue[256];
	char sTXCURRValue[256];
	int rxcount = 0;
	int txcount = 0;
	int vPad;
	FILE *nicCfgFPtr = 0;
	char *header2[] = {"Setting", "Current Value", "Recommended Value", "Applied"};

	gettime(&clk, ctime_buf);

	fprintf(tunLogPtr,"\n%s %s: -------------------------------------------------------------------\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,  "%s %s: ****************Start of Evaluate NIC configuration****************\n\n", ctime_buf, phase2str(current_phase));

	fprintf(tunLogPtr, "%s %*s %25s %20s\n", header2[0], HEADER_SETTINGS_PAD, header2[1], header2[2], header2[3]);
	fflush(tunLogPtr);

	sprintf(aNicSetting,"cat /sys/class/net/%s/tx_queue_len > /tmp/NIC.cfgfile",netDevice);
	system(aNicSetting);

	nicCfgFPtr = fopen("/tmp/NIC.cfgfile","r");
	if (!nicCfgFPtr)
	{
		int save_errno = errno;
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: Could not open file /tmp/NIC.cfgfile to retrieve txqueuelen value, errno = %d...\n", ctime_buf, phase2str(current_phase), save_errno);
	}
	else 
		{
			while((nread = getline(&line, &len, nicCfgFPtr)) != -1) 
			{ //1st keyword txqueuelen
				char sValue[256];
				int cfg_val = 0;
				//printf("Retrieved line of length %zu:\n", nread);
				//printf("&%s&",line);
				strcpy(sValue,line);
				if (sValue[strlen(sValue)-1] == '\n')
					sValue[strlen(sValue)-1] = 0; 
				
				cfg_val = atoi(sValue);
				if (cfg_val == 0) //wasn't set properly
				{
					int save_errno = errno;
					gettime(&clk, ctime_buf);
					fprintf(tunLogPtr,"%s %s: Value for txqueuelen is invalid, value is %s, errno = %d...\n", ctime_buf, phase2str(current_phase), sValue, save_errno);
				}
				else
					{
						int vPad = SETTINGS_PAD_MAX-(strlen("txqueuelen"));
						fprintf(tunLogPtr,"%s", "txqueuelen"); //redundancy for visual
						fprintf(tunLogPtr,"%*s", vPad, sValue);

						if (rec_txqueuelen > cfg_val)
						{
							fprintf(tunLogPtr,"%26d %20c\n", rec_txqueuelen, gApplyNicTuning);
							if (gApplyNicTuning == 'y')
							{
								//Apply Inital DefSys Tuning
								sprintf(aNicSetting,"ifconfig %s txqueuelen %d", netDevice, rec_txqueuelen);
								printf("%s\n",aNicSetting);
								//system(aNicSetting);
							}
						}
						else
							fprintf(tunLogPtr,"%26d %20s\n", rec_txqueuelen, "na");
					}	

				//should only be one item
				break;
			}
	

			if (TEST)                         
				sprintf(aNicSetting,"ethtool --show-ring %s  > /tmp/NIC.cfgfile",testNetDevice);
			else
				sprintf(aNicSetting,"ethtool --show-ring %s  > /tmp/NIC.cfgfile",netDevice);

			system(aNicSetting);
			nicCfgFPtr = freopen("/tmp/NIC.cfgfile","r", nicCfgFPtr);

			while((nread = getline(&line, &len, nicCfgFPtr)) != -1) 
			{ //2nd and 3rd keywords RX and tx ring buffer size
				int count = 0, ncount = 0;
		
				if (strstr(line,"RX:") && rxcount == 0)
				{
					rxcount++;

					while (!isdigit(line[count])) count++;

					while (isdigit(line[count]))
					{
						sRXMAXValue[ncount] = line[count];
						ncount++;
						count++;
					}

					sRXMAXValue[ncount] = 0;
				}
				else
					if (strstr(line,"RX:"))
					{
						rxcount++;
					
						while (!isdigit(line[count])) count++;

						while (isdigit(line[count]))
						{
							sRXCURRValue[ncount] = line[count];
							ncount++;
							count++;
						}

						sRXCURRValue[ncount] = 0;
					}
					else
						if (strstr(line,"TX:") && txcount == 0)
						{
							txcount++;
						
							while (!isdigit(line[count])) count++;

							while (isdigit(line[count]))
							{
								sTXMAXValue[ncount] = line[count];
								ncount++;
								count++;
							}

							sTXMAXValue[ncount] = 0;
						}
						else
							if (strstr(line,"TX:"))
							{
								//should be the last thing I need
								int cfg_max_val = 0;
								int cfg_cur_val = 0;

								txcount++;
							
								while (!isdigit(line[count])) count++;

								while (isdigit(line[count]))
								{
									sTXCURRValue[ncount] = line[count];
									ncount++;
									count++;
								}

								sTXCURRValue[ncount] = 0;
								
								cfg_max_val = atoi(sRXMAXValue);
								cfg_cur_val = atoi(sRXCURRValue);
						
								vPad = SETTINGS_PAD_MAX-(strlen("ring_buffer_RX"));
								fprintf(tunLogPtr,"%s", "ring_buffer_RX"); //redundancy for visual
								fprintf(tunLogPtr,"%*s", vPad, sRXCURRValue);

								if (cfg_max_val > cfg_cur_val)
								{
									fprintf(tunLogPtr,"%26d %20c\n", cfg_max_val, gApplyNicTuning);
									if (gApplyNicTuning == 'y')
									{
										//Apply Inital DefSys Tuning
                            							sprintf(aNicSetting,"ethtool -G %s rx %d", netDevice, cfg_max_val);
                            							printf("%s\n",aNicSetting);
                            							//system(aNicSetting);
									}
								}
								else
									fprintf(tunLogPtr,"%26d %20s\n", cfg_max_val, "na");
								
								cfg_max_val = atoi(sTXMAXValue);
								cfg_cur_val = atoi(sTXCURRValue);

								vPad = SETTINGS_PAD_MAX-(strlen("ring_buffer_TX"));
								fprintf(tunLogPtr,"%s", "ring_buffer_TX"); //redundancy for visual
								fprintf(tunLogPtr,"%*s", vPad, sTXCURRValue);

								if (cfg_max_val > cfg_cur_val)
								{
									fprintf(tunLogPtr,"%26d %20c\n", cfg_max_val, gApplyNicTuning);
									if (gApplyNicTuning == 'y')
									{
										//Apply Inital DefSys Tuning
                            							sprintf(aNicSetting,"ethtool -G %s tx %d", netDevice, cfg_max_val);
                            							printf("%s\n",aNicSetting);
                            							//system(aNicSetting);
									}
								}
								else
									fprintf(tunLogPtr,"%26d %20s\n", cfg_max_val, "na");

								//should be the last thing I need
								break;
							}	
							else
								continue;	
			}
			
			if (TEST)                         
				sprintf(aNicSetting,"ethtool --show-features %s | grep large-receive-offload > /tmp/NIC.cfgfile",testNetDevice);
			else
				sprintf(aNicSetting,"ethtool --show-features %s | grep large-receive-offload > /tmp/NIC.cfgfile",netDevice);

			system(aNicSetting);
			nicCfgFPtr = freopen("/tmp/NIC.cfgfile","r", nicCfgFPtr);

			while((nread = getline(&line, &len, nicCfgFPtr)) != -1) 
			{ //4th keyword: RX and tx ring buffer size
				int count = 0, ncount = 0;
				char *q;
				char sLROValue[256];
				char * recommended_val = "on";

				q = line + strlen("large-receive-offload");
				strcpy(sLROValue,q);

				while (!isalpha(q[count])) count++;

				while (isalpha(q[count]))
				{
					sLROValue[ncount] = q[count];
					ncount++;
					count++;
				}

				sLROValue[ncount] = 0;

				vPad = SETTINGS_PAD_MAX-(strlen("large-receive-offload"));
				fprintf(tunLogPtr,"%s", "large-receive-offload"); //redundancy for visual
				fprintf(tunLogPtr,"%*s", vPad, sLROValue);

				if (strcmp(recommended_val, sLROValue) != 0)
				{
					fprintf(tunLogPtr,"%26s %20c\n", recommended_val, gApplyNicTuning);
					if (gApplyNicTuning == 'y')
					{
						//Apply Inital DefSys Tuning
						sprintf(aNicSetting,"ethtool -K %s lro %s", netDevice, recommended_val);
                   				printf("%s\n",aNicSetting);
                   				//system(aNicSetting);
					}
				}
				else
					fprintf(tunLogPtr,"%26s %20s\n", recommended_val, "na");
								
				//should be only one line in the file
				break;
			}	

			fclose(nicCfgFPtr);	
			system("rm -f /tmp/NIC.cfgfile"); //remove file after use
		}

		fprintf(tunLogPtr,"\n%s %s: *****************End of Evaluate NIC configuration*****************\n", ctime_buf, phase2str(current_phase));
		fprintf(tunLogPtr,  "%s %s: -------------------------------------------------------------------\n\n", ctime_buf, phase2str(current_phase));

		if (line)
			free(line);

	return;
}

void * fDoRunTalkToKernel(void * vargp)
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

/***** HTTP *************/
void check_req(http_s *h, char aResp[])
{
	FIOBJ r = http_req2str(h);
	time_t clk;
	char ctime_buf[27];
	char * pReqData = fiobj_obj2cstr(r).data;
	
	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Received Data from Http Client***\nData is:\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"%s", pReqData);

	if (strstr(pReqData,"GET /-t"))
	{
		/* TODO: Apply tuning */
		strcpy(aResp,"Recommended Tuning applied!!!\n");
	
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to apply recommended Tuning***\n", ctime_buf, phase2str(current_phase));
		fprintf(tunLogPtr,"%s %s: ***Applying recommended Tuning now***\n", ctime_buf, phase2str(current_phase));
		/* TODO: Apply tuning */
	}
	else
		{
			strcpy(aResp,"Received something else!!!\n");
		
			gettime(&clk, ctime_buf);
			fprintf(tunLogPtr,"%s %s: ***Received some kind of request from Http Client***\n", ctime_buf, phase2str(current_phase));
			fprintf(tunLogPtr,"%s %s: ***Applying some kind of request***\n", ctime_buf, phase2str(current_phase));
		}


return;
}

/* TODO: edit this function to handle HTTP data and answer Websocket requests.*/
static void on_http_request(http_s *h) 
{
	char aTheResp[512];	
  	check_req(h, aTheResp);
	/* set the response and send it (finnish vs. destroy). */
  	http_send_body(h, aTheResp, strlen(aTheResp));
}

/* starts a listeninng socket for HTTP connections. */
void initialize_http_service(void) 
{
	time_t clk;
	char ctime_buf[27];
  	char aListenPort[32];	

	/* listen for inncoming connections */
	sprintf(aListenPort,"%d",gAPI_listen_port);
	if (http_listen(aListenPort, NULL, .on_request = on_http_request) == -1) 
	{
    		/* listen failed ?*/
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***ERROR: facil couldn't initialize HTTP service (already running?)...***\n", ctime_buf, phase2str(current_phase));
		return;
  	}
#if 0
  if (http_listen(fio_cli_get("-p"), fio_cli_get("-b"),
                  .on_request = on_http_request,
                  .max_body_size = fio_cli_get_i("-maxbd") * 1024 * 1024,
                  .ws_max_msg_size = fio_cli_get_i("-max-msg") * 1024,
                  .public_folder = fio_cli_get("-public"),
                  .log = fio_cli_get_bool("-log"),
                  .timeout = fio_cli_get_i("-keep-alive"),
                  .ws_timeout = fio_cli_get_i("-ping")) == -1) {
    /* listen failed ?*/
    perror("ERROR: facil couldn't initialize HTTP service (already running?)");
    exit(1);
  }
#endif
}

void * fDoRunHttpServer(void * vargp)
{
	//int * fd = (int *) vargp;
	time_t clk;
	char ctime_buf[27];

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Http Server ...***\n", ctime_buf, phase2str(current_phase));
	//catch_sigint();
	initialize_http_service();
	/* start facil */
	fio_start(.threads = 1, .workers = 0);
	return ;
}


int main(int argc, char **argv) 
{

	char *pDevName = "/dev/tuningMod";
	int fd; 
	int vRetFromKernelThread, vRetFromKernelJoin;
	int vRetFromRunBpfThread, vRetFromRunBpfJoin;
	int vRetFromRunHttpServerThread, vRetFromRunHttpServerJoin;
	pthread_t doRunTalkToKernelThread_id, doRunBpfCollectionThread_id, doRunHttpServerThread_id;
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
	fDoNicTuning();
	fDoBiosTuning();

	gettime(&clk, ctime_buf);
	current_phase = LEARNING;
	
	fd = open(pDevName, O_RDWR,0);

	if (fd > 0)
	{
		vRetFromKernelThread = pthread_create(&doRunTalkToKernelThread_id, NULL, fDoRunTalkToKernel, &fd);
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

#if 0
	{
		// in case the user wants to apply recommended settings after??? Maybe we use. We'll see
		int x =0;
		FILE * fApplyDefTunPtr = 0;
		if (aApplyDefTunCount)
		{
			fApplyDefTunPtr = fopen("/tmp/applyDefFile","w"); //open and close to wipe out file - other ways to do this, but this should work...
			if (!fApplyDefTunPtr)
			{
				int save_errno = errno;
				fprintf(tunLogPtr, "%s %s: Could not open */tmp/applyDefFile* for writing, errno = %d***\n", ctime_buf, phase2str(current_phase), save_errno);
				goto leave;
			}

			fprintf(fApplyDefTunPtr, "%d\n",aApplyDefTunCount+2);

			for (x = 0; x < aApplyDefTunCount; x++)
				fprintf(fApplyDefTunPtr, "%s\n",aApplyDefTun2DArray[x]);

			fclose(fApplyDefTunPtr);
		}
	}
leave:
#endif

#ifdef USING_PERF_EVENT_ARRAY
	vRetFromRunBpfThread = pthread_create(&doRunBpfCollectionThread_id, NULL, fDoRunBpfCollectionPerfEventArray, &sArgv);
#else //Using Map Type RINGBUF
	vRetFromRunBpfThread = pthread_create(&doRunBpfCollectionThread_id, NULL, fDoRunBpfCollectionRingBuf, &sArgv);;
#endif

	//Start Http server Thread	
	vRetFromRunHttpServerThread = pthread_create(&doRunHttpServerThread_id, NULL, fDoRunHttpServer, &sArgv);

	if (vRetFromKernelThread == 0)
    		vRetFromKernelJoin = pthread_join(doRunTalkToKernelThread_id, NULL);

	if (vRetFromRunBpfThread == 0)
    		vRetFromRunBpfJoin = pthread_join(doRunBpfCollectionThread_id, NULL);
	
	if (vRetFromRunHttpServerThread == 0)
    		vRetFromRunHttpServerJoin = pthread_join(doRunHttpServerThread_id, NULL);

	if (fd > 0)
		close(fd);

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: Closing tuning Log***\n", ctime_buf, phase2str(current_phase));
	fclose(tunLogPtr);

return 0;
}

