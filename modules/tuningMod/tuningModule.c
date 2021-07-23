#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/completion.h>
#include <linux/kthread.h>
#include <linux/errno.h>

MODULE_LICENSE("Tuning BSD/GPL");

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

void TuningModule__Wrapper_Sleep( unsigned long duration )
{
  DECLARE_WAIT_QUEUE_HEAD(wq);
  wait_event_timeout(wq, 0, duration);
}

DECLARE_COMPLETION(RFU_side_completion);
DECLARE_WAIT_QUEUE_HEAD(RFU_Thread_Queue);
static int RFU_side_stop_flag = 0;
atomic_t RFU_Thread_Queue_Flag = ATOMIC_INIT(0);

DECLARE_COMPLETION(RFC_side_completion);
DECLARE_WAIT_QUEUE_HEAD(RFC_Thread_Queue);
static int RFC_side_stop_flag = 0;
atomic_t RFC_Thread_Queue_Flag = ATOMIC_INIT(0);

static int tuning_open(struct inode*, struct file*);
static int tuning_release(struct inode*, struct file*);
static ssize_t tuning_read(struct file*, char*, size_t, loff_t*);
static ssize_t tuning_write(struct file*, const char*, size_t, loff_t*);

static struct file_operations fops = {
	.open = tuning_open,
	.read = tuning_read,
	.write = tuning_write,
	.release = tuning_release,
};

static int major;

// 50 jiffies = 200 msecs
#define WAIT_TIMEOUT    HZ/5

void TuningModule_Wrapper_Sleep( unsigned long duration )
{
  DECLARE_WAIT_QUEUE_HEAD(wq);
  wait_event_timeout(wq, 0, duration);
}

int Process_Event_From_Userspace(void){
	static unsigned long count = 0;

	TuningModule_Wrapper_Sleep((unsigned long)2500);
	printk(KERN_ALERT "***In process event from Userspace*** %ld\n", count);

	return 0;
}

int Process_Event_From_Collector(void){
	static unsigned long count = 0;

	TuningModule_Wrapper_Sleep((unsigned long)2000);
	printk(KERN_ALERT "***In process event from Collector*** %ld\n", count);

	return 0;
}

/*------------------------------------------------
d) ;
------------------------------------------------*/
static struct task_struct *rfu_Thread_task  ;
static int Read_From_Userspace_Thread_Loop( void *p )
{
int j;

   ISSUE_WARNING "Read_From_Userspace_Thread_Loop) is being started.\n" ) ;


   while( 1 ){

      wait_event_timeout(RFU_Thread_Queue, atomic_dec_and_test(&RFU_Thread_Queue_Flag), WAIT_TIMEOUT);

        j = Process_Event_From_Userspace() ;
        //atomic_set(&RFU_Thread_Queue_Flag,1);
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
int j;

   ISSUE_WARNING "Read_From_Userspace_Thread_Loop) is being started.\n" ) ;


   while( 1 ){

      wait_event_timeout(RFC_Thread_Queue, atomic_dec_and_test(&RFC_Thread_Queue_Flag), WAIT_TIMEOUT);

        j = Process_Event_From_Collector() ;
        //atomic_set(&RFU_Thread_Queue_Flag,1);
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

	printk(KERN_INFO "tuningModule has been loaded %d\n", major);

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
	printk(KERN_INFO "Sorry, tuningModule is read only\n");
	return -EFAULT;

}

static ssize_t tuning_read(struct file *filep, char *buffer, 
											size_t len, loff_t *offset){

	int errors = 0;
	char *message = "You have entered the tuningModule realm... ";
	int message_len = strlen(message);

	errors = copy_to_user(buffer, message, message_len);

	return errors == 0 ? message_len : -EFAULT;
}

module_init(tuningModule_init);
module_exit(tuningModule_exit);

