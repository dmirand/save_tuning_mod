#define USING_PERF_EVENT_ARRAY2

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
#include <sys/wait.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <arpa/inet.h>


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

//Looks like because of the ringbuf stuff
//#include "../libbpf/src/libbpf.h"

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_kern_user.h"
#include "bpf_util.h" /* bpf_num_possible_cpus */

typedef struct {
	int argc;
	char ** argv;
} sArgv_t;

#ifdef USING_PERF_EVENT_ARRAY2
#include "../../int-sink/src/shared/int_defs.h"
#include "../../int-sink/src/shared/filter_defs.h"

enum ARGS{
	CMD_ARG,
	BPF_MAPS_DIR_ARG,
	MAX_ARG_COUNT
};

struct threshold_maps
{
	int flow_thresholds;
	int hop_thresholds;
	int flow_counters;
};

#define MAP_DIR "/sys/fs/bpf/test_maps"
#define HOP_LATENCY_DELTA 20000
#define FLOW_LATENCY_DELTA 50000
#define QUEUE_OCCUPANCY_DELTA 80
#define FLOW_SINK_TIME_DELTA 1000000000

#define INT_DSCP (0x17)

#define PERF_PAGE_COUNT 512
#define MAX_FLOW_COUNTERS 512

void sample_func(struct threshold_maps *ctx, int cpu, void *data, __u32 size);
void lost_func(struct threshold_maps *ctx, int cpu, __u64 cnt);
void print_hop_key(struct hop_key *key);

void * fDoRunBpfCollectionPerfEventArray2(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	int perf_output_map;
	int int_dscp_map;
	struct perf_buffer *pb;
	struct threshold_maps maps = {};
open_maps: {
	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: Opening maps.\n", ctime_buf, phase2str(current_phase));
	//maps.counters = bpf_obj_get(MAP_DIR "/counters_map");
	fprintf(tunLogPtr,"%s %s: Opening flow_counters_map.\n", ctime_buf, phase2str(current_phase));
	maps.flow_counters = bpf_obj_get(MAP_DIR "/flow_counters_map");
	if (maps.flow_counters < 0) { goto close_maps; }
	fprintf(tunLogPtr,"%s %s: Opening flow_thresholds_map.\n", ctime_buf, phase2str(current_phase));
	maps.flow_thresholds = bpf_obj_get(MAP_DIR "/flow_thresholds_map");
	if (maps.flow_thresholds < 0) { goto close_maps; }
	fprintf(tunLogPtr,"%s %s: Opening hop_thresholds_map.\n", ctime_buf, phase2str(current_phase));
	maps.hop_thresholds = bpf_obj_get(MAP_DIR "/hop_thresholds_map");
	if (maps.hop_thresholds < 0) { goto close_maps; }
	fprintf(tunLogPtr,"%s %s: Opening perf_output_map.\n", ctime_buf, phase2str(current_phase));
	perf_output_map = bpf_obj_get(MAP_DIR "/perf_output_map");
	if (perf_output_map < 0) { goto close_maps; }
	fprintf(tunLogPtr,"%s %s: Opening int_dscp_map.\n", ctime_buf, phase2str(current_phase));
	int_dscp_map = bpf_obj_get(MAP_DIR "/int_dscp_map");
	if (int_dscp_map < 0) { goto close_maps; }
	}
set_int_dscp: {
	fprintf(tunLogPtr,"%s %s: Setting INT DSCP.\n", ctime_buf, phase2str(current_phase));
	__u32 int_dscp = INT_DSCP;
	__u32 zero_value = 0;
	bpf_map_update_elem(int_dscp_map, &int_dscp, &zero_value, BPF_NOEXIST);
    }
open_perf_event: {
	fprintf(tunLogPtr,"%s %s: Opening perf event buffer.\n", ctime_buf, phase2str(current_phase));
#if 0
	struct perf_buffer_opts opts = {
	(perf_buffer_sample_fn)sample_func,
	(perf_buffer_lost_fn)lost_func,
	&maps
	};
#else
	struct perf_buffer_opts opts;
	opts.sample_cb = (perf_buffer_sample_fn)sample_func;
	opts.lost_cb = (perf_buffer_lost_fn)lost_func;
	opts.ctx = &maps;
#endif
	pb = perf_buffer__new(perf_output_map, PERF_PAGE_COUNT, &opts);
	if (pb == 0) { goto close_maps; }
	}
perf_event_loop: {
	fprintf(tunLogPtr,"%s %s: Running perf event loop.\n", ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
 	int err = 0;
	do {
	err = perf_buffer__poll(pb, 100);
	//err = perf_buffer__poll(pb, 500);
	}
	while(err >= 0);
	fprintf(tunLogPtr,"%s %s: Exited perf event loop with err %d..\n", ctime_buf, phase2str(current_phase), -err);
	}
close_maps: {
	fprintf(tunLogPtr,"%s %s: Closing maps.\n", ctime_buf, phase2str(current_phase));
	if (maps.flow_counters <= 0) { goto exit_program; }
	close(maps.flow_counters);
	if (maps.flow_thresholds <= 0) { goto exit_program; }
	close(maps.flow_thresholds);
	if (maps.hop_thresholds <= 0) { goto exit_program; }
	close(maps.hop_thresholds);
	if (perf_output_map <= 0) { goto exit_program; }
	close(perf_output_map);
	if (int_dscp_map <= 0) { goto exit_program; }
	close(int_dscp_map);
	if (pb == 0) { goto exit_program; }
	perf_buffer__free(pb);
	}
exit_program: {
	return ((char *)0);
	}
}

static __u32 vHighest_Rtt = 0;
void sample_func(struct threshold_maps *ctx, int cpu, void *data, __u32 size)
{
	void *data_end = data + size;
	__u32 data_offset = 0;
	struct hop_key hop_key;
	__u32 vCurrent_Rtt = 0;

	if(data + data_offset + sizeof(hop_key) > data_end) return;

	memcpy(&hop_key, data + data_offset, sizeof(hop_key));
	data_offset += sizeof(hop_key);

	struct flow_thresholds flow_threshold_update = {
		0,
		FLOW_LATENCY_DELTA,
		0,
		FLOW_SINK_TIME_DELTA,
		0
	};

	hop_key.hop_index = 0;
	
	while (data + data_offset + sizeof(struct int_hop_metadata) <= data_end)
	{
		struct int_hop_metadata *hop_metadata_ptr = data + data_offset;
		data_offset += sizeof(struct int_hop_metadata);

		struct hop_thresholds hop_threshold_update = {
			ntohs(hop_metadata_ptr->egress_time) - ntohs(hop_metadata_ptr->ingress_time),
			HOP_LATENCY_DELTA,
			ntohs(hop_metadata_ptr->queue_info) & 0xffffff,
			QUEUE_OCCUPANCY_DELTA,
			ntohs(hop_metadata_ptr->switch_id)
		};

		bpf_map_update_elem(ctx->hop_thresholds, &hop_key, &hop_threshold_update, BPF_ANY);
		if(hop_key.hop_index == 0) { flow_threshold_update.sink_time_threshold = ntohs(hop_metadata_ptr->ingress_time); }
		flow_threshold_update.hop_latency_threshold += ntohs(hop_metadata_ptr->egress_time) - ntohs(hop_metadata_ptr->ingress_time);
		print_hop_key(&hop_key);
		hop_key.hop_index++;
	}

	flow_threshold_update.total_hops = hop_key.hop_index;
	bpf_map_update_elem(ctx->flow_thresholds, &hop_key.flow_key, &flow_threshold_update, BPF_ANY);
	struct counter_set empty_counter = {};
	bpf_map_update_elem(ctx->flow_counters, &(hop_key.flow_key), &empty_counter, BPF_NOEXIST);
	vCurrent_Rtt = flow_threshold_update.hop_latency_threshold * 2; //double up for now to simulate 2 way value
	fprintf(stdout, "CURRENT_RTT = %d\n",vCurrent_Rtt);
}

void lost_func(struct threshold_maps *ctx, int cpu, __u64 cnt)
{
	fprintf(stderr, "Missed %llu sets of packet metadata.\n", cnt);
}

void print_flow_key(struct flow_key *key)
{
	fprintf(stdout, "Flow Key:\n");
	fprintf(stdout, "\tegress_switch:%X\n", key->switch_id);
	fprintf(stdout, "\tegress_port:%hu\n", key->egress_port);
	fprintf(stdout, "\tvlan_id:%hu\n", key->vlan_id);
}

void print_hop_key(struct hop_key *key)
{
	fprintf(stdout, "Hop Key:\n");
	print_flow_key(&(key->flow_key));
	fprintf(stdout, "\thop_index: %X\n", key->hop_index);
}

#elif defined(USING_PERF_EVENT_ARRAY1)
static const char *__doc__ = "Tuning Module Userspace program\n"
        " - Finding xdp_stats_map via --dev name info\n"
        " - Has a Tuning Module counterpart in the kernel\n";

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,       NULL, 'h' },
		"Show help", false},

	{{"dev",         required_argument, NULL, 'd' },
		"Operate on device <ifname>", "<ifname>", true},

	{{"quiet",       no_argument,       NULL, 'q' },
		"Quiet mode (no output)"},

	{{0, 0, NULL,  0 }}
};

void read_buffer_sample_perf(void *ctx, int cpu, void *data, unsigned int len) 
{
	time_t clk;
	char ctime_buf[27];
	struct int_telemetry *evt = (struct int_telemetry *)data;
	int	 do_something = 0;

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: %s::: \n", ctime_buf, phase2str(current_phase), "MetaData from Collector Module:");
	fprintf(tunLogPtr,"%s %s: ::: switch %d egress port %d ingress port %d ingress time %d egress time %d queue id %d queue_occupancy %d\n", ctime_buf, phase2str(current_phase), evt->switch_id, evt->egress_port_id, evt->ingress_port_id, evt->ingress_time, evt->egress_time, evt->queue_id, evt->queue_occupancy);
	fflush(tunLogPtr);
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

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"\n%s %s: Starting Collection of perf event array thread***\n", ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);

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
	fflush(tunLogPtr);

	if (gTuningMode) 
		current_phase = TUNING;

	while (1) 
	{
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		//sleep(gInterval);
	}

cleanup:
	perf_buffer__free(pb);
	//if (err) err++; //get rid of silly warning
	return (void *)7;
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
	
	gettime(&clk, ctime_buf);

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

#if defined(RUN_KERNEL_MODULE)
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
#endif

/***** HTTP *************/
void check_req(http_s *h, char aResp[])
{
	FIOBJ r = http_req2str(h);
	time_t clk;
	char ctime_buf[27];
	char aHttpRequest[256];
	char * pReqData = fiobj_obj2cstr(r).data;
	int count = 0;
	char aNicSettingFromHttp[512];
	char aNumber[16];
	
	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Received Data from Http Client***\nData is:\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"%s", pReqData);

	memset(aNumber,0,sizeof(aNumber));

	if (strstr(pReqData,"GET /-t"))
	{
		//Apply tuning
		strcpy(aResp,"Recommended Tuning applied!!!\n");
	
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to apply recommended Tuning***\n", ctime_buf, phase2str(current_phase));
		fprintf(tunLogPtr,"%s %s: ***Applying recommended Tuning now***\n", ctime_buf, phase2str(current_phase));
		sprintf(aHttpRequest,"sh ./user_menu.sh");
		system(aHttpRequest);
	}
	else
		if (strstr(pReqData,"GET /-b#rx#"))
		{
			/* Change rx ring buffer size */
			char *p = (pReqData + sizeof("GET /-b#rx#")) - 1;
			while (isdigit(*p))
			{
				aNumber[count++] = *p;
				p++;
			}


			sprintf(aResp,"Changed rx ring buffer size of %s to %s!\n", netDevice, aNumber);
			gettime(&clk, ctime_buf);
			fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change RX ring buffer size of %s to %s***\n", ctime_buf, phase2str(current_phase), netDevice, aNumber);
			fprintf(tunLogPtr,"%s %s: ***Changing RX buffer size now***\n", ctime_buf, phase2str(current_phase));
			sprintf(aNicSettingFromHttp,"ethtool -G %s rx %s", netDevice, aNumber);
			
			fprintf(tunLogPtr,"%s %s: ***Doing *%s***\n", ctime_buf, phase2str(current_phase), aNicSettingFromHttp);
			system(aNicSettingFromHttp);
		}
		else
			if (strstr(pReqData,"GET /-b#tx#"))
			{
				/* Change tx ring buffer size */
				char *p = (pReqData + sizeof("GET /-b#tx#")) - 1;
				while (isdigit(*p))
				{
					aNumber[count++] = *p;
					p++;
				}

				sprintf(aResp,"Changed tx ring buffer size of %s to %s!\n", netDevice, aNumber);
		
				gettime(&clk, ctime_buf);
				fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change TX ring buffer size of %s to %s***\n", ctime_buf, phase2str(current_phase), netDevice, aNumber);
				fprintf(tunLogPtr,"%s %s: ***Changing TX buffer size now***\n", ctime_buf, phase2str(current_phase));
				sprintf(aNicSettingFromHttp,"ethtool -G %s tx %s", netDevice, aNumber);
			
				fprintf(tunLogPtr,"%s %s: ***Doing *%s***\n", ctime_buf, phase2str(current_phase), aNicSettingFromHttp);
				system(aNicSettingFromHttp);
			}
			else
				{
					strcpy(aResp,"Received something else!!!\n");
		
					gettime(&clk, ctime_buf);
					fprintf(tunLogPtr,"%s %s: ***Received some kind of request from Http Client***\n", ctime_buf, phase2str(current_phase));
					fprintf(tunLogPtr,"%s %s: ***Applying some kind of request***\n", ctime_buf, phase2str(current_phase));
				}

	fflush(tunLogPtr);
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
	fflush(tunLogPtr);
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
	fflush(tunLogPtr);
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
	sprintf(try,"bpftrace -e \'BEGIN { @name;} kprobe:dev_get_stats { $nd = (struct net_device *) arg0; @name = $nd->name; } kretprobe:dev_get_stats /@name == \"%s\"/ { $rtnl = (struct rtnl_link_stats64 *) retval; $rx_bytes = $rtnl->rx_bytes; $tx_bytes = $rtnl->tx_bytes; printf(\"%s %s\\n\", $tx_bytes, $rx_bytes); time(\"%s\"); exit(); } END { clear(@name); }\'",netDevice,"%lu","%lu","%S");
	/*sprintf(try,"bpftrace -e \'BEGIN { @name;} kfunc:dev_get_stats { $nd = (struct net_device *) args->dev; @name = $nd->name; } kretfunc:dev_get_stats /@name == \"%s\"/ { $nd = (struct net_device *) args->dev; $rtnl = (struct rtnl_link_stats64 *) args->storage; $rx_bytes = $rtnl->rx_bytes; $tx_bytes = $rtnl->tx_bytes; printf(\"%s %s\\n\", $tx_bytes, $rx_bytes); time(\"%s\"); exit(); } END { clear(@name); }\'",netDevice,"%lu","%lu","%S");*/

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

			//sleep(1);
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
				secs_passed = 1;
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

void * fDoRunHelperDtn(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	struct stat sb;

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting HelperDtn thread ...***\n", ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
	//check if already running
	system("ps -ef | grep -v grep | grep help_dtn.sh  > /tmp/help_dtn_alive.out 2>/dev/null");
	stat("/tmp/help_dtn_alive.out", &sb);
	if (sb.st_size == 0); //good - no runaway process
	else //kill it
	{
		printf("Killing runaway help_dtn.sh process\n");
		system("pkill -9 help_dtn.sh");
	}

	system("rm -f /tmp/help_dtn_alive.out");
	sleep(1); //relax

restart_vfork:
	printf("About to fork new help_dtn.sh process\n");
	pid_t pid = vfork();
	if (pid == 0)
	{
		if (execlp("./help_dtn.sh", "help_dtn.sh", netDevice, (char*) NULL) == -1)
		{
			perror("Could not execlp");
			exit(-1);;
		}
	}
#if 0
	else
		{
			printf("I'm the parent process; the child got pid %d.\n", pid);
			//  return 0;
		}
#endif

	while (1)
	{
		sleep(5); //check every 5 seconds to see if process alive
		system("ps -ef | grep -v grep | grep -v defunct | grep help_dtn.sh  > /tmp/help_dtn_alive.out 2>/dev/null");
		stat("/tmp/help_dtn_alive.out", &sb);
		if (sb.st_size == 0) //process died, restart it
		{
			int status;
			system("rm -f /tmp/help_dtn_alive.out");
			wait(&status);
			goto restart_vfork;
		}

		system("rm -f /tmp/help_dtn_alive.out");
	}

return ((char *) 0);
}

int main(int argc, char **argv) 
{
	int vRetFromRunBpfThread, vRetFromRunBpfJoin;
	int vRetFromRunHttpServerThread, vRetFromRunHttpServerJoin;
	int vRetFromRunGetThresholdsThread, vRetFromRunGetThresholdsJoin;
	int vRetFromRunHelperDtnThread, vRetFromRunHelperDtnJoin;
	pthread_t doRunBpfCollectionThread_id, doRunHttpServerThread_id, doRunGetThresholds_id, doRunHelperDtn_id;
	sArgv_t sArgv;
	time_t clk;
	char ctime_buf[27];
#ifdef RUN_KERNEL_MODULE
	char *pDevName = "/dev/tuningMod";
	int fd = 0; 
	int vRetFromKernelThread, vRetFromKernelJoin;
	pthread_t doRunTalkToKernelThread_id;
#endif

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
	
	gettime(&clk, ctime_buf);
	current_phase = LEARNING;

#if defined(RUN_KERNEL_MODULE)
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
#endif

	fflush(tunLogPtr);

#if defined(USING_PERF_EVENT_ARRAY1) //testing with a test bpf object
	vRetFromRunBpfThread = pthread_create(&doRunBpfCollectionThread_id, NULL, fDoRunBpfCollectionPerfEventArray, &sArgv);
#elif defined(USING_PERF_EVENT_ARRAY2) //current int-sink compatible
	vRetFromRunBpfThread = pthread_create(&doRunBpfCollectionThread_id, NULL, fDoRunBpfCollectionPerfEventArray2, &sArgv);
#else //Using Map Type RINGBUF
	vRetFromRunBpfThread = pthread_create(&doRunBpfCollectionThread_id, NULL, fDoRunBpfCollectionRingBuf, &sArgv);;
#endif

	//Start Http server Thread	
	vRetFromRunHttpServerThread = pthread_create(&doRunHttpServerThread_id, NULL, fDoRunHttpServer, &sArgv);
	//Start Threshhold monitoring	
	vRetFromRunGetThresholdsThread = pthread_create(&doRunGetThresholds_id, NULL, fDoRunGetThresholds, &sArgv); 
	//Start Helper functioning	
	vRetFromRunHelperDtnThread = pthread_create(&doRunHelperDtn_id, NULL, fDoRunHelperDtn, &sArgv); 

#if defined(RUN_KERNEL_MODULE)
	if (vRetFromKernelThread == 0)
    		vRetFromKernelJoin = pthread_join(doRunTalkToKernelThread_id, NULL);
#endif
	if (vRetFromRunBpfThread == 0)
    		vRetFromRunBpfJoin = pthread_join(doRunBpfCollectionThread_id, NULL);
	
	if (vRetFromRunHttpServerThread == 0)
    		vRetFromRunHttpServerJoin = pthread_join(doRunHttpServerThread_id, NULL);
	
	if (vRetFromRunGetThresholdsThread == 0)
    		vRetFromRunGetThresholdsJoin = pthread_join(doRunGetThresholds_id, NULL);

	if (vRetFromRunHelperDtnThread == 0)
    		vRetFromRunHelperDtnJoin = pthread_join(doRunHelperDtn_id, NULL);

#if defined(RUN_KERNEL_MODULE)
	if (fd > 0)
		close(fd);
#endif

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: Closing tuning Log***\n", ctime_buf, phase2str(current_phase));
	fclose(tunLogPtr);

return 0;
}

