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
	char aMessage[512];

	int fd;
	int len = strlen(aMessage);
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
		strcpy(aMessage,"This is a message...");
		result = write(fd,aMessage,strlen(aMessage));
		if (result < 0)
			fprintf(tunuser_ptr,"There was an error writing***\n");
		else
			fprintf(tunuser_ptr,"***GoodW**, message written = ***%s***\n", aMessage);

		memset(aMessage,0,512);
		result = read(fd,aMessage,512);
		if (result < 0)
			fprintf(tunuser_ptr,"There was an error readin***\n");
		else
			fprintf(tunuser_ptr,"***GoodR**, message read = ***%s***\n", aMessage);
		
	}
		
	if (fd > 0)
		close(fd);

	fprintf(tunuser_ptr, "tuning Log closed***\n");
	fclose(tunuser_ptr);

return 0;
}

