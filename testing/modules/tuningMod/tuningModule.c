#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/completion.h>
#include <linux/kthread.h>
#include <linux/errno.h>
#include <linux/random.h>
#include <linux/semaphore.h>

MODULE_LICENSE("GPL");

#define DEVICE_NAME	"tuningMod"
#define ISSUE_WARNING \
   printk(  "<1>\nWarning From " ) ; \
   printk(  __FILE__ ) ;\
   printk(  "<1> " ) ;\
   printk(  __FUNCTION__ ) ;\
   printk(  "<1>() " ) ; \
   printk(  "<1>Line# %d\n", __LINE__ ) ;\
   printk(  "<1>" ) ;\
   printk(

// 50 jiffies = 200 msecs
#define WAIT_TIMEOUT    HZ/5

DECLARE_COMPLETION(RFU_side_completion);
DECLARE_WAIT_QUEUE_HEAD(RFU_Thread_Queue);
static int RFU_side_stop_flag = 0;
atomic_t RFU_Thread_Queue_Flag = ATOMIC_INIT(0);

DECLARE_COMPLETION(RFC_side_completion);
DECLARE_WAIT_QUEUE_HEAD(RFC_Thread_Queue);
static int RFC_side_stop_flag = 0;
atomic_t RFC_Thread_Queue_Flag = ATOMIC_INIT(0);

DEFINE_SEMAPHORE(readlock);

static int tuning_open(struct inode*, struct file*);
static int tuning_release(struct inode*, struct file*);
static ssize_t tuning_read(struct file*, char*, size_t, loff_t*);
static ssize_t tuning_write(struct file*, const char*, size_t, loff_t*);

extern unsigned long avenrun[];         /* Load averages */

static struct file_operations fops = {
	.open = tuning_open,
	.read = tuning_read,
	.write = tuning_write,
	.release = tuning_release,
};

static int major;
static char test[512];
static char writetest[512];

// 50 jiffies = 200 msecs
#define WAIT_TIMEOUT    HZ/5

void TuningModule_Wrapper_Sleep( unsigned long duration )
{
  DECLARE_WAIT_QUEUE_HEAD(wq);
  wait_event_timeout(wq, 0, duration);
}

int Do_Initial_Tuning(void)
{
	TuningModule_Wrapper_Sleep((unsigned long)3000);
	printk(KERN_ALERT "***In Do_Initial_Tuning***\n");

	return 0;
}

int Process_Event_From_Userspace(void)
{
	static unsigned long count = 0;

	count++;
	printk(KERN_ALERT "***In process event from Userspace*** %ld\n", count);
	printk(KERN_INFO "%ld bytes written... Bytes written were **%s**\n",strlen(test),test);

	return 0;
}

int Process_Event_From_Collector(void)
{
	static unsigned long count = 0;
	unsigned int x;
	unsigned long y;

	count++;
	get_random_bytes(&x, sizeof(x));
	y = x % 8000; /* print from 0 to 7999 */
	TuningModule_Wrapper_Sleep(y);
	down(&readlock);
	sprintf(writetest,"***Processed event from Kernel*** %ld:%ld, %ld.%03ld", count,y, (avenrun[0] >> 11), ((avenrun[0] & ((1 << 11) - 1)) * 1000) >> 11);
	up(&readlock);

	return 0;
}

static int ready_to_go = 0;
static struct task_struct *dit_Thread_task  ;
static int Do_Initial_Tuning_Thread( void *p )
{

   	ISSUE_WARNING "Do_Initial_Tuning_Thread is being started.\n" ) ;


   	Do_Initial_Tuning() ;
 	ready_to_go = 1; 

  	return 0;
}
	
/*------------------------------------------------
Read_From_Userspace_Thread_Loop( void *p );
------------------------------------------------*/
static struct task_struct *rfu_Thread_task  ;
static int Read_From_Userspace_Thread_Loop( void *p )
{
int x;
long j;

   ISSUE_WARNING "Read_From_Userspace_Thread_Loop) is being started.\n" ) ;

   while(1) {
   
   		if (ready_to_go)
			break;
	
		for(x = 0; x < 4096; x++);//do something

		schedule(); //give up the cpu until ready
   }

	//go ahead	
   while( 1 ){

      j = wait_event_timeout(RFU_Thread_Queue, atomic_dec_and_test(&RFU_Thread_Queue_Flag), WAIT_TIMEOUT);

	if (j)
        x = Process_Event_From_Userspace() ;

      if( RFU_side_stop_flag )
         break ;
   };
   
	complete_and_exit(&RFU_side_completion, 0);
   	return 0;
}
	
/*------------------------------------------------
Read_From_Collector_Thread_Loop(void * p) ;
------------------------------------------------*/
static struct task_struct *rfc_Thread_task  ;
static int Read_From_Collector_Thread_Loop( void *p )
{
int j,x;

   ISSUE_WARNING "Read_From_Collector_Thread_Loop) is being started.\n" ) ;
   
   while(1) {
   
   		if (ready_to_go)
			break;
	
		for(x = 0; x < 4096; x++);//do something

		schedule(); //give up the cpu until ready
   }

   while( 1 ){

      wait_event_timeout(RFC_Thread_Queue, atomic_dec_and_test(&RFC_Thread_Queue_Flag), WAIT_TIMEOUT);

        j = Process_Event_From_Collector() ;
        //atomic_set(&RFC_Thread_Queue_Flag,1);
      if( RFC_side_stop_flag )
         break ;
   };
   
	complete_and_exit(&RFC_side_completion, 0);
   	return 0;
}
	
static int tuningModule_init(void) {
	major = register_chrdev(0, DEVICE_NAME, &fops);

	if (major < 0) 
	{
		printk(KERN_ALERT "***tuningModule load failed***\n");
		return major;
	}

	//Initialization of writetest
	strcpy(writetest,"Entering tuningModule realm...");
	printk(KERN_INFO "tuningModule has been loaded %d\n", major);
      
	dit_Thread_task = kthread_run( Do_Initial_Tuning_Thread, NULL, "do_initial_Tuning_Thread");
    if (IS_ERR(dit_Thread_task) ){
    	return PTR_ERR(dit_Thread_task ) ;
    };
      

    rfu_Thread_task = kthread_run( Read_From_Userspace_Thread_Loop, NULL, "read_From_Userspace_Thread_Loop");
    if (IS_ERR(rfu_Thread_task) ){
    	return PTR_ERR(rfu_Thread_task ) ;
    };
      
	rfc_Thread_task = kthread_run( Read_From_Collector_Thread_Loop, NULL, "read_From_Collector_Thread_Loop");
    if (IS_ERR(rfc_Thread_task) ){
    	return PTR_ERR(rfc_Thread_task ) ;
    };


	return 0;
}

static void tuningModule_exit(void) {
	ISSUE_WARNING "TuningModule is being Removed\n");

	RFU_side_stop_flag  = 1   ;
	wait_for_completion(&RFU_side_completion);
	
	RFC_side_stop_flag  = 1   ;
	wait_for_completion(&RFC_side_completion);
	unregister_chrdev(major, DEVICE_NAME);

	return;
}

static int tuning_open(struct inode *inodep, struct file *filep){
	printk(KERN_INFO "tuningModule has been opened\n");
	return 0;
}

static int tuning_release(struct inode *inodep, struct file *filep){
	printk(KERN_INFO "tuningModule has been released/closed\n");
	return 0;
}

static ssize_t tuning_write(struct file *filep, const char *buffer, 
											size_t len, loff_t *offset){
	if (copy_from_user(test,buffer,len))
	{
		printk(KERN_INFO "Sorry, error writing to tuningModule\n");
		return -EFAULT;
	}

	test[len] = 0;	
	atomic_set(&RFU_Thread_Queue_Flag,1);
	return len;
}

static ssize_t tuning_read(struct file *filep, char *buffer, 
											size_t len, loff_t *offset){

	int message_len, errors = 0;

	if (down_interruptible(&readlock))
		return -ERESTARTSYS;

 	message_len = strlen(writetest);
	errors = copy_to_user(buffer, writetest, message_len);
	up(&readlock);

	return errors == 0 ? message_len : -EFAULT;
}

module_init(tuningModule_init);
module_exit(tuningModule_exit);

