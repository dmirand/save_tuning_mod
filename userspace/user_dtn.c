#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
/* This works with tuning Module */

FILE * tunuser_ptr = 0;
int main() 
{

	char *pDevName = "/dev/tuningMod";
	char *pMessage = "this is a test";
	int fd;
	int len = strlen(pMessage);
	int result;

	tunuser_ptr = fopen("/tmp/tuningLog","a");
	if (!tunuser_ptr)
	{
		printf("Could not open tuning Logfile, exiting...\n");
		exit(-1);
	}


	fprintf(tunuser_ptr, "tuning Log opened***\n");
	
	fd = open(pDevName, O_RDWR,0);

	if (fd > 0)
	{
		result = write(fd,pMessage,len);
		if (result < 0)
			printf("There was an error writing***\n");
		else
			printf("***Good writing***\n");
		
	}
		
	if (fd > 0)
		close(fd);

	fprintf(tunuser_ptr, "tuning Log closed***\n");
	fclose(tunuser_ptr);

return 0;
}

