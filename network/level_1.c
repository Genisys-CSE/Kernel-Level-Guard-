#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Genisys");
MODULE_DESCRIPTION("K-Guard: Unified Firewall (Smart Logging)");

// CONFIGURATION
#define RATE_LIMIT_THRESHOLD 5
#define TIME_WINDOW_HZ HZ

struct connection_entry {
    __be32 ip;
    unsigned long last_seen;
    int count;
    int has_logged;          
    struct list_head list;
};

static LIST_HEAD(conn_list);
static DEFINE_SPINLOCK(conn_lock);
static struct nf_hook_ops net_hook;

static int check_rate_limit(__be32 src_ip)
{
    struct connection_entry *entry;
    struct connection_entry *new_entry;
    int is_allowed = 1; 

    spin_lock(&conn_lock);

    // 1. Search existing IP
    list_for_each_entry(entry, &conn_list, list) {
        if (entry->ip == src_ip) {
            
            // Check Timer
            if (time_before(jiffies, entry->last_seen + TIME_WINDOW_HZ)) {
                entry->count++;
                
                if (entry->count > RATE_LIMIT_THRESHOLD) {
                    is_allowed = 0; // BLOCK
                    
                    // --- SMART LOGGING ---
                    // Only print if we haven't complained yet this second
                    if (entry->has_logged == 0) {
                        printk(KERN_ALERT "[K-GUARD] DoS BLOCKED: High Traffic from %pI4 (Silencing further logs...)\n", &src_ip);
                        entry->has_logged = 1; // Mark as done
                    }
                }
            } else {
                // Timer Reset
                entry->last_seen = jiffies;
                entry->count = 1;
                entry->has_logged = 0; // <--- NEW: Reset log flag for next second
            }
            
            spin_unlock(&conn_lock);
            return is_allowed;
        }
    }

    // 2. New IP
    new_entry = kmalloc(sizeof(struct connection_entry), GFP_ATOMIC);
    if (new_entry) {
        new_entry->ip = src_ip;
        new_entry->last_seen = jiffies;
        new_entry->count = 1;
        new_entry->has_logged = 0;
        list_add(&new_entry->list, &conn_list);
    }
    
    spin_unlock(&conn_lock);
    return 1;
}

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;

    if (!skb) return NF_ACCEPT;
    ip_header = ip_hdr(skb);
    if (!ip_header) return NF_DROP;

    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);
        if (!tcp_header) return NF_DROP;

        // --- FAST CHECKS (Logs always print for these because they are rare) ---
        if (tcp_header->doff < 5) return NF_DROP;

        if (tcp_header->syn && tcp_header->fin) {
            printk(KERN_ALERT "[K-GUARD] BLOCKED: Illegal SYN+FIN from %pI4\n", &ip_header->saddr);
            return NF_DROP;
        }

        if (tcp_header->fin && tcp_header->urg && tcp_header->psh) {
            printk(KERN_ALERT "[K-GUARD] BLOCKED: XMAS Scan from %pI4\n", &ip_header->saddr);
            return NF_DROP;
        }

        if (!tcp_header->syn && !tcp_header->ack && !tcp_header->fin && 
            !tcp_header->rst && !tcp_header->urg && !tcp_header->psh) {
            printk(KERN_ALERT "[K-GUARD] BLOCKED: NULL Scan from %pI4\n", &ip_header->saddr);
            return NF_DROP;
        }

        // --- RATE LIMIT CHECK ---
        if (tcp_header->syn && !tcp_header->ack) {
            if (check_rate_limit(ip_header->saddr) == 0) {
                // No printk here! It's handled inside the function now.
                return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}

static void flush_list(void)
{
    struct connection_entry *entry, *tmp;
    spin_lock(&conn_lock);
    list_for_each_entry_safe(entry, tmp, &conn_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock(&conn_lock);
}

static int __init kguard_init(void)
{
    printk(KERN_INFO "K-Guard: Smart Logging Firewall Loaded.\n");
    net_hook.hook = hook_func;
    net_hook.hooknum = NF_INET_PRE_ROUTING;
    net_hook.pf = PF_INET;
    net_hook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &net_hook);
    return 0;
}

static void __exit kguard_exit(void)
{
    nf_unregister_net_hook(&init_net, &net_hook);
    flush_list();
    printk(KERN_INFO "K-Guard: Unloaded.\n");
}

module_init(kguard_init);
module_exit(kguard_exit);
