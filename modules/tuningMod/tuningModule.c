#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("Tuning BSD/GPL");

#define DEVICE_NAME	"tuningMod"

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
	
static int tuningModule_init(void) {
	major = register_chrdev(0, DEVICE_NAME, &fops);

	if (major < 0) 
	{
		printk(KERN_ALERT "***tuningModule load failed***\n");
		return major;
	}

	printk(KERN_INFO "tuningModule has been loaded %d\n", major);
	return 0;
}

static void tuningModule_exit(void) {
	unregister_chrdev(major, DEVICE_NAME);
	printk(KERN_INFO "tuningModule has been unloaded\n");
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

