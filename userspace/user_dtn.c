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

#include "user_dtn.h"
FILE * tunLogPtr = 0;
void gettime(time_t *clk, char *ctime_buf)
{
	*clk = time(NULL);
	ctime_r(clk,ctime_buf);
	ctime_buf[24] = ':';
}

/******HTTP server *****/
#include "fio.h"
#include "http.h"
void initialize_http_service(void);
/**********************/

#define USING_PERF_EVENT_ARRAY 1

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

char netDevice[128];
static unsigned long rx_bits_per_sec = 0, tx_bits_per_sec = 0;

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
	char aHttpRequest[256];
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
		sprintf(aHttpRequest,"sh ./user_menu.sh");
		system(aHttpRequest);
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
	return ((char *)0);
}

void * fDoRunGetThresholds(void * vargp)
{
	//int * fd = (int *) vargp;
	time_t clk;
	char ctime_buf[27];

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Check Threshold thread ...***\n", ctime_buf, phase2str(current_phase));
	char buffer[128];
	FILE *pipe;
	int before = 0;
	int now = 0;
	time_t secs_passed = 1;
	unsigned long rx_before, rx_now, rx_bytes_tot;
	unsigned long tx_before, tx_now, tx_bytes_tot;
	char try[1024];
	int stage = 0;

	rx_before =  rx_now = rx_bytes_tot = rx_bits_per_sec = 0;
	tx_before =  tx_now =  tx_bytes_tot = tx_bits_per_sec = 0;
	sprintf(try,"bpftrace -e \'BEGIN { @name;} kfunc:dev_get_stats { $nd = (struct net_device *) args->dev; @name = $nd->name; } kretfunc:dev_get_stats /@name == \"%s\"/ { $nd = (struct net_device *) args->dev; $rtnl = (struct rtnl_link_stats64 *) args->storage; $rx_bytes = $rtnl->rx_bytes; $tx_bytes = $rtnl->tx_bytes; printf(\"%s %s\\n\", $tx_bytes, $rx_bytes); time(\"%s\"); exit(); } END { clear(@name); }\'",netDevice,"%lu","%lu","%S");
	/*sprintf(try,"bpftrace -e \'BEGIN { @name;} kfunc:dev_get_stats { $nd = (struct net_device *) args->dev; @name = $nd->name; } kretfunc:dev_get_stats /@name == \"%s\"/ { $nd = (struct net_device *) args->dev; $rtnl = (struct rtnl_link_stats64 *) args->storage; $rx_bytes = $rtnl->rx_bytes; $tx_bytes = $rtnl->tx_bytes; printf(\"%s %s\\n\", $tx_bytes, $rx_bytes); exit(); } END { clear(@name); }\'",netDevice,"%lu","%lu");*/

start:
	secs_passed = 0;
	//before = time((time_t *)0);
	pipe = popen(try,"r");
	if (!pipe)
	{
		printf("popen failed!\n");
		return ((char *) 0);
	}
	// read for 2 lines of process:
	while (!feof(pipe))
	{
		// use buffer to read and add to result
		if (fgets(buffer, 128, pipe) != NULL);
		else
			{
				printf("Not working****\n");
				return ((char *) 0);
			}

 		if (fgets(buffer, 128, pipe) != NULL)
		{
			sscanf(buffer,"%lu %lu", &tx_before, &rx_before);
			fgets(buffer, 128, pipe);
			sscanf(buffer,"%d", &before);
			pclose(pipe);

			sleep(1);
			pipe = popen(try,"r");
			if (!pipe)
			{
				printf("popen failed!\n");
				return ((char *) 0);
			}
			//now = time((time_t *)0);
			stage = 1;
			break;
		}
		else
			{
				printf("Not working****\n");
				return ((char *) 0);
			}
	}

	while (!feof(pipe) && stage)
	{
		// use buffer to read and add to result
		if (fgets(buffer, 128, pipe) != NULL);
		else
			{
				printf("Not working****\n");
				return ((char *) 0);
			}
		if (fgets(buffer, 128, pipe) != NULL)
		{
			sscanf(buffer,"%lu %lu", &tx_now, &rx_now);
			fgets(buffer, 128, pipe);
			sscanf(buffer,"%d", &now);

			tx_bytes_tot =  tx_now - tx_before;
			rx_bytes_tot =  rx_now - rx_before;

			if (now < before) //seconds started over
			{
				secs_passed = (60 - before) + now;
			}
			else
				secs_passed = now - before;

			if (!secs_passed) 
				secs_passed = 1;;
#if 1
			tx_bits_per_sec = ((8 * tx_bytes_tot) / 1024) / secs_passed;
			rx_bits_per_sec = ((8 * rx_bytes_tot) / 1024) / secs_passed;;
			printf("TX %s: %lu kb/s RX %s: %lu kb/s, secs_passed %lu\n", netDevice, tx_bits_per_sec, netDevice, rx_bits_per_sec, secs_passed);

			pclose(pipe);
			break;
}
#else
			tx_bits_per_sec = ((tx_bytes_tot) / 1024) / secs_passed; //really bytes per sec
			rx_bits_per_sec = ((rx_bytes_tot) / 1024) / secs_passed; //really bytes per sec
			printf("RX eno2: %lu KB/s TX eno2: %lu KB/s\n", rx_bits_per_sec, tx_bits_per_sec);
			pclose(pipe);
			stage = 0;
			break;
#endif
			else
				{
					printf("Not working****\n");
					return ((char *) 0);
				}
		}

		if (stage)
		{
			stage = 0;
			goto start;
		}

		printf("Problems*** stage not set...\n");

return ((char *) 0);
}

int main(int argc, char **argv) 
{

	char *pDevName = "/dev/tuningMod";
	int fd; 
	int vRetFromKernelThread, vRetFromKernelJoin;
	int vRetFromRunBpfThread, vRetFromRunBpfJoin;
	int vRetFromRunHttpServerThread, vRetFromRunHttpServerJoin;
	int vRetFromRunGetThresholdsThread, vRetFromRunGetThresholdsJoin;
	pthread_t doRunTalkToKernelThread_id, doRunBpfCollectionThread_id, doRunHttpServerThread_id, doRunGetThresholds_id;
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
		
	user_assess(argc, argv);
#if 0
	fDoGetUserCfgValues();

	fDoSystemTuning();
	fDoNicTuning();
	fDoBiosTuning();
#endif
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

#ifdef USING_PERF_EVENT_ARRAY
	vRetFromRunBpfThread = pthread_create(&doRunBpfCollectionThread_id, NULL, fDoRunBpfCollectionPerfEventArray, &sArgv);
#else //Using Map Type RINGBUF
	vRetFromRunBpfThread = pthread_create(&doRunBpfCollectionThread_id, NULL, fDoRunBpfCollectionRingBuf, &sArgv);;
#endif

	//Start Http server Thread	
	vRetFromRunHttpServerThread = pthread_create(&doRunHttpServerThread_id, NULL, fDoRunHttpServer, &sArgv);
	
	vRetFromRunGetThresholdsThread = pthread_create(&doRunGetThresholds_id, NULL, fDoRunGetThresholds, &sArgv); 

	if (vRetFromKernelThread == 0)
    		vRetFromKernelJoin = pthread_join(doRunTalkToKernelThread_id, NULL);

	if (vRetFromRunBpfThread == 0)
    		vRetFromRunBpfJoin = pthread_join(doRunBpfCollectionThread_id, NULL);
	
	if (vRetFromRunHttpServerThread == 0)
    		vRetFromRunHttpServerJoin = pthread_join(doRunHttpServerThread_id, NULL);
	
	if (vRetFromRunGetThresholdsThread == 0)
    		vRetFromRunGetThresholdsJoin = pthread_join(doRunGetThresholds_id, NULL);

	if (fd > 0)
		close(fd);

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: Closing tuning Log***\n", ctime_buf, phase2str(current_phase));
	fclose(tunLogPtr);

return 0;
}

