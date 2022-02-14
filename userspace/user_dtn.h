//extern enum workflow_phases;

#define WORKFLOW_NAMES_MAX      4

enum workflow_phases {
        STARTING,
        ASSESSMENT,
        LEARNING,
        TUNING,
};
extern const char *phase2str(enum workflow_phases phase);
extern FILE * tunLogPtr;
extern enum workflow_phases current_phase;
extern int gInterval;
extern int gAPI_listen_port;
extern char gTuningMode;
extern char netDevice[];



extern void gettime(time_t *clk, char *ctime_buf);
extern int user_assess(int argc, char **argv);
extern void fDoGetUserCfgValues(void);
extern void fDoBiosTuning(void);
extern void fDoNicTuning(void);
extern void fDoSystemtuning(void);
extern void fDo_lshw(void);
