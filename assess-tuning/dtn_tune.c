#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <bits/stdint-uintn.h>
#include <ctype.h>
#include <getopt.h>
#include <time.h>
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
static char gTuningMode = 0;
static char gApplyDefSysTuning = 'n';

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

#define PAD_MAX	49
#define HEADER_PAD	45
#define CONST_PAD	12
    gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: Final user config values after using settings from %s:\n",ctime_buf, phase2str(current_phase), pUserCfgFile);
	fprintf(tunLogPtr,"%s %s: A configured value of -1 means the setting was not configured and the default value will be used.\n",ctime_buf, phase2str(current_phase));
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
					gTuningMode = 1;
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

#define bbr 		0
#define fq		 	1
#define htcp	 	2
char *aStringval[] ={"bbr", "fq", "htcp"};

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
host_tuning_vals_t aTuningNumsToUse[TUNING_NUMS] = {
    {"net.core.rmem_max",   			67108864,          -1,      	0},
    {"net.core.wmem_max",   			67108864,          -1,      	0},
    {"net.ipv4.tcp_mtu_probing",			   1,          -1,      	0},
    {"net.ipv4.tcp_congestion_control",	    htcp, 		   -1,			0}, //uses #defines to help
    {"net.core.default_qdisc",		          fq, 		   -1,			0}, //uses #defines
    {"net.ipv4.tcp_rmem",       			4096,      	87380,   33554432},
    {"net.ipv4.tcp_wmem",       			4096,       65536,   33554432},
    {"MTU",		                               0, 		   84, 			0} //Will leave here but not using for now
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
	fprintf(tunLogPtr, "%s %s: ***NOTE - Some settings have a minimum, default and maximum values, while others only have a single value***\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr, "%s %s: ***NOTE - If the recommended value is less than or equal to the current value, no changes will be made for that setting***\n\n", ctime_buf, phase2str(current_phase));

#define SETTINGS_PAD_MAX 58
#define HEADER_SETTINGS_PAD  50
	fprintf(tunLogPtr, "%s %*s %25s %20s\n", header2[0], HEADER_SETTINGS_PAD, header2[1], header2[2], header2[3]);
	fflush(tunLogPtr);

    while ((nread = getline(&line, &len, tunDefSysCfgPtr)) != -1) {
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
										//printf("%s\n",aApplyDefTun);	
										system(aApplyDefTun);
									}
								}
						}
						else
							{//has min, default and max values - get them...
								//Let's parse the value stringand get the min, etc. separately
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
											//printf("%s\n",aApplyDefTun);	
											system(aApplyDefTun);
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
                                {//has min, default and max values - get them...
                                //Let's parse the value stringand get the min, etc. separately
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
							fprintf(tunLogPtr,"%*s", vPad, value);	
							fprintf(tunLogPtr,"%26s %20c\n",aStringval[aTuningNumsToUse[count].minimum], gApplyDefSysTuning);
							if (gApplyDefSysTuning == 'y')
							{
								//Apply Inital DefSys Tuning
								sprintf(aApplyDefTun,"sysctl -w %s=%s",setting,aStringval[aTuningNumsToUse[count].minimum]);
								//printf("%s\n",aApplyDefTun);	
								system(aApplyDefTun);
							}
						}
						else
							{
								fprintf(tunLogPtr,"%*s %25s %20s\n", vPad, value, aStringval[aTuningNumsToUse[count].minimum], "na");	
#if 0
								if (gApplyDefSysTuning == 'y')
								{
									//Apply Inital Def
									//No need to apply - already set...
									sprintf(aApplyDefTun,"no need to apply for %s=%s since already set...",setting, aStringval[aTuningNumsToUse[count].minimum]);
									//printf("%s\n",aApplyDefTun);	
									system(aApplyDefTun);
								}
#endif
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
	fprintf(tunLogPtr,"%s %s: ***'sudo dmidecode' and/or 'sudo lshw'. \n\n", ctime_buf, phase2str(current_phase));

	fprintf(tunLogPtr, "\n%s %s: ***Closing Tuning Module default system configuration file***\n", ctime_buf, phase2str(current_phase));
	fclose(tunDefSysCfgPtr);

    gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"\n%s %s: ***End of Default System Tuning***\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"%s %s: ***----------------------------***\n\n", ctime_buf, phase2str(current_phase));

	free(line);
	return;
}

int main(int argc, char **argv) 
{

	time_t clk;
	char ctime_buf[27];

	tunLogPtr = fopen("/tmp/tuningLog","w");
	if (!tunLogPtr)
	{
		printf("Could not open tuning Logfile, exiting...\n");
		exit(-1);
	}

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: tuning Log opened***\n", ctime_buf, phase2str(current_phase));

	gettime(&clk, ctime_buf);
	current_phase = ASSESSMENT;

	fDoGetUserCfgValues();

	fDoSystemTuning();

	gettime(&clk, ctime_buf);
	current_phase = LEARNING;
	
	fflush(tunLogPtr);

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: Closing tuning Log***\n", ctime_buf, phase2str(current_phase));
	fclose(tunLogPtr);

return 0;
}

