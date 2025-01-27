#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/delay.h>

#define PROC_NAME "vuln3"
#define MAX_COUNTERS 5

struct counter {
    int value;
    bool is_locked;
    char name[32];
};

static struct counter *counters[MAX_COUNTERS];
static int counter_count = 0;
static bool is_exploited = false;

// Vulnerable: No synchronization between check and use
static int find_counter_by_name(const char *name) {
    int i;
    for (i = 0; i < MAX_COUNTERS; i++) {
        if (counters[i] && strncmp(counters[i]->name, name, 31) == 0)
            return i;
    }
    return -1;
}

static int find_free_slot(void) {
    int i;
    for (i = 0; i < MAX_COUNTERS; i++) {
        if (!counters[i])
            return i;
    }
    return -1;
}

static ssize_t vuln_write(struct file *file, const char __user *buffer, size_t length, loff_t *offset) {
    char cmd;
    char name[32];
    int slot, idx;
    int value;

    if (length < 2)
        return -EINVAL;

    if (copy_from_user(&cmd, buffer, 1))
        return -EFAULT;

    switch(cmd) {
        case 'C': // Create counter
            if (length > 33)
                return -EINVAL;

            memset(name, 0, sizeof(name));
            if (copy_from_user(name, buffer + 1, length - 1))
                return -EFAULT;

            // Race condition: Time-of-check to time-of-use (TOCTOU)
            if (find_counter_by_name(name) >= 0)
                return -EEXIST;

            slot = find_free_slot();
            if (slot < 0)
                return -ENOMEM;

            // Artificial delay to make race condition easier to hit
            mdelay(100);

            counters[slot] = kmalloc(sizeof(struct counter), GFP_KERNEL);
            if (!counters[slot])
                return -ENOMEM;

            strncpy(counters[slot]->name, name, 31);
            counters[slot]->value = 0;
            counters[slot]->is_locked = false;
            counter_count++;

            return length;

        case 'I': // Increment counter
            if (length < 33)
                return -EINVAL;

            memset(name, 0, sizeof(name));
            if (copy_from_user(name, buffer + 1, length - 1))
                return -EFAULT;

            idx = find_counter_by_name(name);
            if (idx < 0)
                return -ENOENT;

            // Race condition: No proper locking
            if (counters[idx]->is_locked)
                return -EBUSY;

            counters[idx]->is_locked = true;
            value = counters[idx]->value;
            
            // Artificial delay to make race condition easier to hit
            mdelay(50);
            
            counters[idx]->value = value + 1;
            counters[idx]->is_locked = false;

            // Check for exploitation
            if (counters[idx]->value > 100) {
                is_exploited = true;
                printk(KERN_INFO "Level3: Race condition successfully exploited!\n");
            }

            return length;

        case 'R': // Read counter
            if (length < 33)
                return -EINVAL;

            memset(name, 0, sizeof(name));
            if (copy_from_user(name, buffer + 1, length - 1))
                return -EFAULT;

            idx = find_counter_by_name(name);
            if (idx < 0)
                return -ENOENT;

            printk(KERN_INFO "Counter %s value: %d\n", name, counters[idx]->value);
            return length;

        case 'D': // Delete counter
            if (length < 33)
                return -EINVAL;

            memset(name, 0, sizeof(name));
            if (copy_from_user(name, buffer + 1, length - 1))
                return -EFAULT;

            idx = find_counter_by_name(name);
            if (idx < 0)
                return -ENOENT;

            kfree(counters[idx]);
            counters[idx] = NULL;
            counter_count--;

            return length;

        default:
            return -EINVAL;
    }
}

static ssize_t vuln_read(struct file *file, char __user *buffer, size_t length, loff_t *offset) {
    const char *message;
    size_t msg_len;

    if (*offset > 0)
        return 0;

    if (is_exploited) {
        message = "CTF{R4c3_C0nd1t10n_1s_Tr1cky}\n";
    } else {
        message = "Not exploited yet! Hint: Race Condition\n";
    }

    msg_len = strlen(message);
    if (copy_to_user(buffer, message, msg_len))
        return -EFAULT;

    *offset = msg_len;
    return msg_len;
}

static const struct proc_ops vuln_fops = {
    .proc_read = vuln_read,
    .proc_write = vuln_write,
};

static int __init vuln_init(void) {
    if (!proc_create(PROC_NAME, 0666, NULL, &vuln_fops))
        return -ENOMEM;

    printk(KERN_INFO "Level3: Vulnerable module loaded! Try to exploit the race condition!\n");
    return 0;
}

static void __exit vuln_exit(void) {
    int i;
    for (i = 0; i < MAX_COUNTERS; i++) {
        if (counters[i]) {
            kfree(counters[i]);
            counters[i] = NULL;
        }
    }
    remove_proc_entry(PROC_NAME, NULL);
    printk(KERN_INFO "Level3: Module unloaded\n");
}

module_init(vuln_init);
module_exit(vuln_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("shadowintel");
MODULE_DESCRIPTION("Level 3 - Race Condition Vulnerability");
