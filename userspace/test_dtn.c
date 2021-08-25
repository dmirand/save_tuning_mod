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

int fTalkToKernel(int fd);

/* start of bpf stuff  ****/
#ifndef PATH_MAX
#define PATH_MAX    4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

#include <locale.h>
#include <time.h>

#include <bpf/bpf.h>
/* Lesson#1: this prog does not need to #include <bpf/libbpf.h> as it only uses
 * the simple bpf-syscall wrappers, defined in libbpf #include<bpf/bpf.h>
 */

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_kern_user.h"
#include "bpf_util.h" /* bpf_num_possible_cpus */


static const struct option_wrapper long_options[] = {
    {{"help",        no_argument,       NULL, 'h' },
     "Show help", false},

    {{"dev",         required_argument, NULL, 'd' },
     "Operate on device <ifname>", "<ifname>", true},

    {{"quiet",       no_argument,       NULL, 'q' },
     "Quiet mode (no output)"},

    {{0, 0, NULL,  0 }}
};

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
        struct timespec t;
        int res;

        res = clock_gettime(CLOCK_MONOTONIC, &t);
        if (res < 0) {
                fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
                exit(EXIT_FAIL);
        }
        return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

struct record {
        __u64 timestamp;
        struct datarec total; /* defined in common_kern_user.h */
};

struct stats_record {
        struct record stats[XDP_ACTION_MAX];
};

static double calc_period(struct record *r, struct record *p)
{
        double period_ = 0;
        __u64 period = 0;

        period = r->timestamp - p->timestamp;
        if (period > 0)
                period_ = ((double) period / NANOSEC_PER_SEC);

        return period_;
}

static void stats_print_header()
{
        /* Print stats "header" */
        printf("%-12s\n", "XDP-action");
}

static void stats_print(__u32 *stats_rec,
                        __u32 *stats_prev, __u32 map_type)
{
        struct record *rec, *prev;
        __u64 packets, bytes;
        double period;
        double pps; /* packets per sec */
        double bps; /* bits per sec */
        int i;

        stats_print_header(); /* Print stats "header" */

		switch (map_type) {
        case BPF_MAP_TYPE_ARRAY:
        {
		    char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
            //" %'11lld Kbytes (%'6.0f Mbits/s)"
            " period:%f, bytes = %ld, packets = %ld, mytest = %ld\n";
            const char *action = action2str(XDP_PASS);
            rec  = &stats_rec->stats[0];
            prev = &stats_prev->stats[0];

            period = calc_period(rec, prev);
            if (period == 0)
                return;

            packets = rec->total.rx_packets - prev->total.rx_packets;
            pps     = packets / period;
        	bytes = rec->total.rx_bytes - prev->total.rx_bytes;

            printf(fmt, action, rec->total.rx_packets, pps, period, bytes, packets, rec->total.rx_tests);
        }
        break;
	
		case BPF_MAP_TYPE_PERCPU_ARRAY:	
        /* Print for each XDP actions stats */
        	for (i = 0; i < XDP_ACTION_MAX; i++)
        	{
                char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
                     " %'11lld Kbytes (%'6.0f Mbits/s)"
                     " period:%f, bytes = %ld, packets = %ld, mytest = %ld\n";
                const char *action = action2str(i);

                rec  = &stats_rec->stats[i];
                prev = &stats_prev->stats[i];

                period = calc_period(rec, prev);
                if (period == 0)
                       return;

                packets = rec->total.rx_packets - prev->total.rx_packets;
                pps     = packets / period;

                bytes   = rec->total.rx_bytes   - prev->total.rx_bytes;
                bps     = (bytes * 8)/ period / 1000000;

                printf(fmt, action, rec->total.rx_packets, pps,
                       rec->total.rx_bytes / 1000 , bps,
                       period, bytes, packets, rec->total.rx_tests);
        	}
        	printf("\n");
		break;

		default:
            fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n",
                map_type);
        return;
        break;
    }
}

/* BPF_MAP_TYPE_ARRAY */
void map_get_value_array(int fd, __u32 key, __u32 *value)
{
        if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
                fprintf(stderr,
                        "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
        }
}

/* BPF_MAP_TYPE_PERCPU_ARRAY */
void map_get_value_percpu_array(int fd, __u32 key, __u32 *value)
{
        /* For percpu maps, userspace gets a value per possible CPU */
        unsigned int nr_cpus = bpf_num_possible_cpus();
        struct datarec values[nr_cpus];
        __u64 sum_bytes = 0;
        __u64 sum_pkts = 0;
		__u64 sum_tests = 0;
        int i;

        if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
                fprintf(stderr,
                        "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
                return;
        }

        /* Sum values from each CPU */
        for (i = 0; i < nr_cpus; i++) {
                sum_pkts  += values[i].rx_packets;
                sum_bytes += values[i].rx_bytes;
				sum_tests += values[i].rx_tests;
        }
        value->rx_packets = sum_pkts;
        value->rx_bytes   = sum_bytes;
		value->rx_tests   = sum_tests;
}

static bool map_collect(int fd, __u32 map_type, __u32 key, __u32 *rec)
{
        __u32 value;

        /* Get time as close as possible to reading map contents */
        rec->timestamp = gettime();

        switch (map_type) {
        case BPF_MAP_TYPE_ARRAY:
                map_get_value_array(fd, key, &value);
                break;
        case BPF_MAP_TYPE_PERCPU_ARRAY:
                map_get_value_percpu_array(fd, key, &value);
                break;
        default:
                fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n",
                        map_type);
                return false;
                break;
        }

        &rec = value;
        return true;
}

static void stats_collect(int map_fd, __u32 map_type,
                          __u32 *stats_rec)
{
        /* Collect all XDP actions stats  */
        __u32 key;

        for (key = 0; key < 256; key++) {
                map_collect(map_fd, map_type, key, &stats_rec[key]);
	}
}

static void stats_poll(int map_fd, __u32 map_type, int interval, int kernel_fd)
{
        __u32 prev[256], record[256] = {0};

        /* Trick to pretty printf with thousands separators use %' */
        setlocale(LC_NUMERIC, "en_US");

        /* Get initial reading quickly */
        stats_collect(map_fd, map_type, record);
        usleep(1000000/4);

        while (1) 
		{
        	prev = record; /* struct copy */
            stats_collect(map_fd, map_type, record);
            stats_print(record, prev, map_type);
            sleep(interval);
			fTalkToKernel(kernel_fd);
            sleep(interval);
        }
}

int fDoRunBpfCollection(int argc, char **argv, int kernel_fd) 
{

    struct bpf_map_info map_expect = { 0 };
    struct bpf_map_info info = { 0 };
    char pin_dir[PATH_MAX];
    int stats_map_fd;
    int interval = 5;
    //int interval = 2;
    int len, err;

    struct config cfg = {
        .ifindex   = -1,
        .do_unload = false,
    };

    /* Cmdline options can change progsec */
    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
    if (cfg.ifindex == -1) {
        fprintf(stderr, "ERR: required option --dev missing\n\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

	/* Use the --dev name as subdir for finding pinned maps */
    len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
    if (len < 0) {
        fprintf(stderr, "ERR: creating pin dirname\n");
        return EXIT_FAIL_OPTION;
    }

	stats_map_fd = open_bpf_map_file(pin_dir, "xdp_test_map", &info);
    if (stats_map_fd < 0) {
        return EXIT_FAIL_BPF;
    }

    /* check map info, e.g. datarec is expected size */
    map_expect.key_size    = sizeof(__u32);
    map_expect.value_size  = sizeof(__u32);
    map_expect.max_entries = 256;
    err = check_map_fd_info(&info, &map_expect);
    if (err) {
        fprintf(stderr, "ERR: map via FD not compatible\n");
        return err;
    }

    if (verbose) {
        printf("\nCollecting stats from BPF map\n");
        printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
               " key_size:%d value_size:%d max_entries:%d\n",
               info.type, info.id, info.name,
               info.key_size, info.value_size, info.max_entries
               );
    }

    stats_poll(stats_map_fd, info.type, interval, kernel_fd);
	return EXIT_OK;
}


/* End of bpf stuff ****/

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
    uint32_t xDefault; //if default is 0, then default and max are nops
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
    {"net.ipv4.tcp_congestion_control",	    htcp, 			0, 			0}, //uses #defines to help
    {"net.core.default_qdisc",		    fq_codel, 			0, 			0}, //uses #defines
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
		
	fprintf(tunLogPtr,"\n\t\t\t***Start of Default System Tuning***\n");
	fprintf(tunLogPtr,"\t\t\t***------------------------------***\n");

	tunDefSysCfgPtr = fopen("/tmp/default_sysctl_config","r");
	if (!tunDefSysCfgPtr)
	{
		fprintf(tunLogPtr,"Could not open Tuning Module default system config file, exiting...\n");
		fclose(tunLogPtr);
		exit(-2);
	}

	fprintf(tunLogPtr, "Tuning Module default system configuration file opened***\n");
	fflush(tunLogPtr);

    while ((nread = getline(&line, &len, tunDefSysCfgPtr)) != -1) {
    	//fprintf(tunLogPtr,"Retrieved line of length %zu:\n", nread);
		//fprintf(tunLogPtr,"&%s&",line);
		p = line;
		q = strchr(line,' '); //search for space	
		len = (q-p) + 1;
		strncpy(setting,p,len);
		if (setting[len-1] == ' ')
			setting[--len] = 0;
		else
			setting[len] = 0;

		fprintf(tunLogPtr,"\nsetting is ***%s***\n",setting);
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
					if(intvalue <= aTuningNumsToUse[count].minimum)
					{
						if (aTuningNumsToUse[count].xDefault == 0) //only one value
						{
							fprintf(tunLogPtr,"Current config value for *%s* is *%s* which is less than the minimum recommendation...\n",setting, value);	
							fprintf(tunLogPtr,"You should change to the recommended setting of *%d* for *%s*.\n",aTuningNumsToUse[count].minimum, setting);
						}
						else
							{//has min, default and max values
								//more work needed			
								fprintf(tunLogPtr,"Current config value for *XXXX***%s* is *%s*...\n",setting, value);	
								fprintf(tunLogPtr,"You should change to the recommended setting of *%s* to *%d\t%d\t%d*.\n",setting, aTuningNumsToUse[count].minimum, aTuningNumsToUse[count].xDefault, aTuningNumsToUse[count].maximum);
							}
					}
				}	
				else
					{ //must be a string
						if (strcmp(value, aStringval[aTuningNumsToUse[count].minimum]) != 0)
						{
							fprintf(tunLogPtr,"Current config value for *%s* is *%s* which is not the same as the recommendation...\n",setting, value);	
							fprintf(tunLogPtr,"You should change to the recommended setting of *%s* for *%s*.\n",aStringval[aTuningNumsToUse[count].minimum], setting);
						}
						else
							{
								fprintf(tunLogPtr,"Current config value for *%s* is *%s* is the same as the recommendation...\n",setting, value);	
							}
							
					}

				found = 1;
				break;
			}
		}

		if (!found)
			fprintf(tunLogPtr,"ERR*** Could not find the following setting **%s**\n", setting);
		
	}
	
	fprintf(tunLogPtr, "\n***Closing Tuning Module default system configuration file***\n");
	fclose(tunDefSysCfgPtr);

	fprintf(tunLogPtr,"\n\t\t\t***End of Default System Tuning***\n");
	fprintf(tunLogPtr,"\t\t\t***----------------------------***\n\n");

	if(line)
		free(line);

	return;
}

int fTalkToKernel(int fd)
{
	int result = 0;
	char aMessage[512];
	strcpy(aMessage,"This is a message...");
	result = write(fd,aMessage,strlen(aMessage));
	if (result < 0)
		fprintf(tunLogPtr,"There was an error writing***\n");
	else
		fprintf(tunLogPtr,"***GoodW**, message written to kernel module = ***%s***\n", aMessage);

	memset(aMessage,0,512);
	result = read(fd,aMessage,512);
	if (result < 0)
		fprintf(tunLogPtr,"There was an error readin***\n");
	else
		fprintf(tunLogPtr,"***GoodR**, message read = ***%s***\n", aMessage);

	fflush(tunLogPtr);
	return result;
}

int main(int argc, char **argv) 
{

	char *pDevName = "/dev/tuningMod";
	int fd, err;

	tunLogPtr = fopen("/tmp/tuningLog","w");
	if (!tunLogPtr)
	{
		printf("Could not open tuning Logfile, exiting...\n");
		exit(-1);
	}
	fprintf(tunLogPtr, "tuning Log opened***\n");

	fprintf(tunLogPtr, "Running gdv.s - Shell script to Get default system valuesh***\n");

	system("sh ./gdv.sh");

	fDoSystemTuning();
	
	fd = open(pDevName, O_RDWR,0);

	if (fd > 0)
		err = fTalkToKernel(fd);
	else
	{
		fprintf(tunLogPtr,"***Error opening kernel device, errno = %dn***\n",errno);
		fprintf(tunLogPtr, "Closing tuning Log and exiting***\n");
		fclose(tunLogPtr);
		exit(-8);
	}
			
	fflush(tunLogPtr);

	err = fDoRunBpfCollection(argc, argv, fd);
	if (err)
	{
		fprintf(tunLogPtr, "***Err %d while starting up bpf Collector***\n",err);
	}


	if (fd > 0)
		close(fd);

	fprintf(tunLogPtr, "Closing tuning Log***\n");
	fclose(tunLogPtr);

return 0;
}

