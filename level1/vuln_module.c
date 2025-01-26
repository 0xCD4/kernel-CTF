#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define PROC_NAME "vuln"
#define BUFFER_SIZE 32

static char kernel_buffer[BUFFER_SIZE];
static int is_exploited = 0;

static ssize_t vuln_write(struct file *file, const char __user *buffer, size_t length, loff_t *offset) {
    char tmp[BUFFER_SIZE];
    
    if (copy_from_user(tmp, buffer, length > BUFFER_SIZE ? BUFFER_SIZE : length)) {
        return -EFAULT;
    }
    
    if (length > BUFFER_SIZE) {
        is_exploited = 1;
        printk(KERN_INFO "Buffer overflow triggered!\n");
    }
    
    memcpy(kernel_buffer, tmp, BUFFER_SIZE);
    return length;
}

static ssize_t vuln_read(struct file *file, char __user *buffer, size_t length, loff_t *offset) {
    const char *message;
    size_t msg_len;

    if (*offset > 0)
        return 0;

    if (is_exploited) {
        message = "CTF{K3rn3l_H4ck1ng_1s_Fun}";
    } else {
        message = "Not exploited yet! Write more than 32 bytes to get the flag.\n";
    }

    msg_len = strlen(message);
    if (copy_to_user(buffer, message, msg_len)) {
        return -EFAULT;
    }

    *offset = msg_len;
    return msg_len;
}

static const struct proc_ops vuln_fops = {
    .proc_read = vuln_read,
    .proc_write = vuln_write,
};

static int __init vuln_init(void) {
    struct proc_dir_entry *entry;
    
    memset(kernel_buffer, 0, BUFFER_SIZE);
    
    entry = proc_create(PROC_NAME, 0666, NULL, &vuln_fops);
    if (!entry) {
        return -ENOMEM;
    }
    
    printk(KERN_INFO "Vulnerable module loaded! Write more than %d bytes to get the flag.\n", BUFFER_SIZE);
    return 0;
}

static void __exit vuln_exit(void) {
    remove_proc_entry(PROC_NAME, NULL);
    printk(KERN_INFO "Module unloaded\n");
}

module_init(vuln_init);
module_exit(vuln_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("shadowintel");
MODULE_DESCRIPTION("Simple Buffer Overflow Module - Level 1");