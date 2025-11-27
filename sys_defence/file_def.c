#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fcntl.h> 
#include <linux/binfmts.h> 
#include <linux/sched/signal.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Genisys");
MODULE_DESCRIPTION("K-Guard: Syscall Firewall (File Shield + No-Exec)");

// --- CONFIGURATION ---
// 1. Files to Protect (No Write Access allowed)
#define PROTECT_1 "shadow"
#define PROTECT_2 "ssh_config"
#define PROTECT_3 "bash"

// 2. Path to Block Execution from
#define BLOCK_EXEC_PATH "/tmp"

// --- HELPER: KILL PROCESS ---
// We use this to stop a process from executing malware in /tmp
static void kill_process(struct task_struct *target_task)
{
    struct kernel_siginfo info;
    if (target_task == NULL) return;

    // Prepare SIGKILL
    memset(&info, 0, sizeof(struct kernel_siginfo));
    info.si_signo = SIGKILL;
    info.si_code = SI_KERNEL;
    info.si_int = 1;

    // Fire!
    send_sig_info(SIGKILL, &info, target_task);
}

// =========================================================================
// HOOK 1: THE INTEGRITY SHIELD (security_file_open)
// Prevents writing to critical files
// =========================================================================

static int hook_open(struct kprobe *p, struct pt_regs *regs)
{
    // Arg 1: struct file *file (DI register)
    struct file *file = (struct file *)regs->di;
    const char *filename;
    int flags;

    if (file && file->f_path.dentry) {
        filename = file->f_path.dentry->d_name.name;
        flags = file->f_flags;

        // Check if trying to WRITE
        if ((flags & O_WRONLY) || (flags & O_RDWR) || (flags & O_CREAT) || (flags & O_TRUNC)) {
            
            // Check Protected List
            if (strcmp(filename, PROTECT_1) == 0 ||
                strcmp(filename, PROTECT_2) == 0 ||
                strcmp(filename, PROTECT_3) == 0) {
                
                printk(KERN_ALERT "[K-GUARD] SHIELD: Blocked modification of '%s' by Process '%s' (PID %d)\n",
                       filename, current->comm, current->pid);

                // Downgrade permissions to Read-Only
                file->f_flags &= ~(O_WRONLY | O_RDWR | O_CREAT | O_TRUNC);
                file->f_flags |= O_RDONLY;
            }
        }
    }
    return 0;
}

// Define the Kprobe for Open
static struct kprobe kp_open = {
    .symbol_name = "security_file_open",
    .pre_handler = hook_open,
};

// =========================================================================
// HOOK 2: THE NO-EXEC GUARD (security_bprm_check)
// Prevents execution from /tmp
// =========================================================================

static int hook_exec(struct kprobe *p, struct pt_regs *regs)
{
    // Arg 1: struct linux_binprm *bprm (DI register)
    // This structure contains details about the program being started.
    struct linux_binprm *bprm = (struct linux_binprm *)regs->di;
    char *pathbuf;
    char *fullname;

    if (bprm && bprm->file) {
        // We need to allocate a buffer to get the full path
        pathbuf = kmalloc(PATH_MAX, GFP_ATOMIC);
        if (!pathbuf) return 0;

        // Convert file struct to full string path (e.g., "/tmp/virus")
        fullname = d_path(&bprm->file->f_path, pathbuf, PATH_MAX);

        // Check if we got a valid string (d_path returns error pointer sometimes)
        if (!IS_ERR(fullname)) {
            
            // CHECK: Does it start with "/tmp"?
            // We use strncmp to check the prefix
            if (strncmp(fullname, BLOCK_EXEC_PATH, strlen(BLOCK_EXEC_PATH)) == 0) {
                
                printk(KERN_ALERT "[K-GUARD] NO-EXEC: Blocked execution of '%s' (PID %d). Killing process.\n",
                       fullname, current->pid);

                // Stop the process immediately
                kill_process(current);
            }
        }

        kfree(pathbuf);
    }
    return 0;
}

// Define the Kprobe for Exec
static struct kprobe kp_exec = {
    .symbol_name = "security_bprm_check",
    .pre_handler = hook_exec,
};

// =========================================================================
// MODULE INIT / EXIT
// =========================================================================

static int __init kguard_sys_init(void)
{
    int ret;

    // Register Hook 1 (Open)
    ret = register_kprobe(&kp_open);
    if (ret < 0) {
        printk(KERN_INFO "K-Guard: Failed to register Open Hook.\n");
        return ret;
    }

    // Register Hook 2 (Exec)
    ret = register_kprobe(&kp_exec);
    if (ret < 0) {
        // Cleanup if second one fails
        unregister_kprobe(&kp_open);
        printk(KERN_INFO "K-Guard: Failed to register Exec Hook.\n");
        return ret;
    }

    printk(KERN_INFO "K-Guard: Syscall Firewall Loaded.\n");
    printk(KERN_INFO "   [+] Shield Active: %s, %s, %s\n", PROTECT_1, PROTECT_2, PROTECT_3);
    printk(KERN_INFO "   [+] No-Exec Active: %s\n", BLOCK_EXEC_PATH);
    
    return 0;
}

static void __exit kguard_sys_exit(void)
{
    unregister_kprobe(&kp_open);
    unregister_kprobe(&kp_exec);
    printk(KERN_INFO "K-Guard: Syscall Firewall Unloaded.\n");
}

module_init(kguard_sys_init);
module_exit(kguard_sys_exit);
