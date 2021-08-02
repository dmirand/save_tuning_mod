#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main() 
{

	char *pDevName = "/dev/tuningMod";
	char *pMessage = "this is a test";
	int fd;
	int len = strlen(pMessage);
	int result;

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

return 0;
}

