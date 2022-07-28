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

#include "../userspace/user_dtn.h"

char gTuningMode = 0;
FILE * tunLogPtr = 0;
void gettime(time_t *clk, char *ctime_buf)
{
        *clk = time(NULL);
        ctime_r(clk,ctime_buf);
        ctime_buf[24] = ':';
}

char netDevice[128];
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
#include "../userspace/common_kern_user.h"
#include "bpf_util.h" /* bpf_num_possible_cpus */

typedef struct {
        int argc;
        char ** argv;
} sArgv_t;

enum workflow_phases current_phase = STARTING;

const char *workflow_names[WORKFLOW_NAMES_MAX] = {
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
        int      do_something = 0;

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
        }

cleanup:
        perf_buffer__free(pb);
        //if (err) err++; //get rid of silly warning
        return (void *)7;
}

int main(int argc, char **argv)
{
        int vRetFromRunBpfThread, vRetFromRunBpfJoin;
        pthread_t doRunBpfCollectionThread_id;
        sArgv_t sArgv;
        time_t clk;
        char ctime_buf[27];

        sArgv.argc = argc;
        sArgv.argv = argv;

        tunLogPtr = fopen("/tmp/perfTuningLog","w");
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

       vRetFromRunBpfThread = pthread_create(&doRunBpfCollectionThread_id, NULL, fDoRunBpfCollectionPerfEventArray, &sArgv);

       if (vRetFromRunBpfThread == 0)
		vRetFromRunBpfJoin = pthread_join(doRunBpfCollectionThread_id, NULL);

               gettime(&clk, ctime_buf);
        fprintf(tunLogPtr, "%s %s: Closing tuning Log***\n", ctime_buf, phase2str(current_phase));
        fclose(tunLogPtr);

return 0;
}
