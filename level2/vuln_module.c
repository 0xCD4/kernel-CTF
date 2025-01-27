#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define PROC_NAME "vuln2"
#define MAX_NOTES 8
#define NOTE_SIZE 64

struct note {
    char content[NOTE_SIZE];
    int id;
    bool is_freed;
};

static struct note *notes[MAX_NOTES];
static int note_count = 0;
static bool is_exploited = false;

static int find_free_slot(void) {
    int i;
    for (i = 0; i < MAX_NOTES; i++) {
        if (!notes[i] || notes[i]->is_freed)
            return i;
    }
    return -1;
}

static ssize_t vuln_write(struct file *file, const char __user *buffer, size_t length, loff_t *offset) {
    char cmd[8];
    int note_id;
    int slot;

    if (length < 2)
        return -EINVAL;

    if (copy_from_user(cmd, buffer, 1))
        return -EFAULT;

    switch(cmd[0]) {
        case 'A': // Add note
            if (length > NOTE_SIZE)
                return -EINVAL;

            slot = find_free_slot();
            if (slot < 0)
                return -ENOMEM;

            notes[slot] = kmalloc(sizeof(struct note), GFP_KERNEL);
            if (!notes[slot])
                return -ENOMEM;

            if (copy_from_user(notes[slot]->content, buffer + 1, length - 1)) {
                kfree(notes[slot]);
                return -EFAULT;
            }

            notes[slot]->id = slot;
            notes[slot]->is_freed = false;
            note_count++;

            return length;

        case 'F': // Free note
            if (copy_from_user(&note_id, buffer + 1, sizeof(int)))
                return -EFAULT;

            if (note_id < 0 || note_id >= MAX_NOTES || !notes[note_id])
                return -EINVAL;

            // UAF vulnerability: mark as freed but don't clear pointer
            notes[note_id]->is_freed = true;
            kfree(notes[note_id]);
            note_count--;

            return length;

        case 'R': // Read note
            if (copy_from_user(&note_id, buffer + 1, sizeof(int)))
                return -EFAULT;

            if (note_id < 0 || note_id >= MAX_NOTES || !notes[note_id])
                return -EINVAL;

            // UAF vulnerability: can read freed notes
            if (notes[note_id]->content[0] == 'E' && 
                notes[note_id]->content[1] == 'X' && 
                notes[note_id]->content[2] == 'P') {
                is_exploited = true;
                printk(KERN_INFO "Level2: Exploitation successful!\n");
            }

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
        message = "CTF{Us3_Aft3r_Fr33_1s_D4ng3r0us}\n";
    } else {
        message = "Not exploited yet! Hint: Use-After-Free\n";
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

    printk(KERN_INFO "Level2: Vulnerable module loaded! Try to exploit the Use-After-Free!\n");
    return 0;
}

static void __exit vuln_exit(void) {
    int i;
    for (i = 0; i < MAX_NOTES; i++) {
        if (notes[i] && !notes[i]->is_freed) {
            kfree(notes[i]);
            notes[i] = NULL;
        }
    }
    remove_proc_entry(PROC_NAME, NULL);
    printk(KERN_INFO "Level2: Module unloaded\n");
}

module_init(vuln_init);
module_exit(vuln_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xCD4");
MODULE_DESCRIPTION("Level 2 - Use After Free Vulnerability");
