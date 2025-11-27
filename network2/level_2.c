#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_arp.h> // Special header for ARP Hooks
#include <linux/if_arp.h>        // ARP Packet Definitions
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Genisys");
MODULE_DESCRIPTION("K-Guard: Anti-MITM (ARP Spoofing Detector)");

// --- CONFIGURATION ---
// Run 'ip route' to find Gateway IP
// Run 'arp -a' to find Gateway MAC
#define GATEWAY_IP "192.168.42.2" 
#define TRUSTED_MAC "\xc0\xa8\x01\x01\xaa\xbb" // Example: Needs raw hex bytes

static struct nf_hook_ops arp_hook;
static unsigned char trusted_gateway_mac[6] = {0x00, 0x50, 0x56, 0xe3, 0x2a, 0x95}; // CHANGE THIS
static __be32 trusted_gateway_ip;

// --- HELPER: CONVERT IP STRING TO INT ---
// (Simplified: In real code, use in_aton or pass as parameter)
// For this skeleton, we will calculate it dynamically in init.

static unsigned int mitm_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct arphdr *arp_header;
    unsigned char *sha; // Sender Hardware Address (MAC)
    unsigned char *sip; // Sender IP Address
    __be32 sender_ip_int;

    if (!skb) return NF_ACCEPT;

    // 1. Get ARP Header
    arp_header = arp_hdr(skb);
    if (!arp_header) return NF_ACCEPT;

    // 2. We only care about ARP REPLIES (Opcode 2)
    // Hackers send fake replies to poison your cache.
    if (ntohs(arp_header->ar_op) != ARPOP_REPLY) {
        return NF_ACCEPT;
    }

    // 3. Extract Fields (ARP headers are variable length, messy pointer math needed)
    // The payload follows the fixed header.
    // [Hardware Type][Protocol Type][...][Sender MAC][Sender IP][Target MAC][Target IP]
    
    // Pointer math to skip the fixed struct and get to data
    sha = (unsigned char *)arp_header + sizeof(struct arphdr);
    sip = (unsigned char *)arp_header + sizeof(struct arphdr) + skb->dev->addr_len;

    // Convert Sender IP bytes to Integer
    sender_ip_int = *(__be32 *)sip;

    // 4. THE MITM CHECK
    // "Does this packet claim to be from the Gateway?"
    if (sender_ip_int == trusted_gateway_ip) {
        
        // "Does the MAC match the Trusted MAC?"
        if (memcmp(sha, trusted_gateway_mac, 6) != 0) {
            
            // NO MATCH! SOMEONE IS LYING!
            printk(KERN_ALERT "[K-GUARD] CRITICAL: MITM DETECTED!\n");
            printk(KERN_ALERT "   Fake Gateway MAC: %pM\n", sha);
            printk(KERN_ALERT "   Real Gateway MAC: %pM\n", trusted_gateway_mac);
            
            return NF_DROP; // SAVE THE SYSTEM
        }
    }

    return NF_ACCEPT;
}

static int __init kguard_mitm_init(void)
{
    // Convert string IP to integer (Hardcoded for skeleton simplicity)
    trusted_gateway_ip = in_aton(GATEWAY_IP);

    printk(KERN_INFO "K-Guard: MITM Protection Active.\n");
    printk(KERN_INFO "   Watching Gateway: %s\n", GATEWAY_IP);
    printk(KERN_INFO "   Trusted MAC: %pM\n", trusted_gateway_mac);

    // Register ARP Hook (Note: NF_ARP, not NF_INET)
    arp_hook.hook = mitm_hook_func;
    arp_hook.hooknum = NF_ARP_IN;    // Filter Incoming ARP
    arp_hook.pf = NFPROTO_ARP;       // ARP Protocol Family
    arp_hook.priority = NF_IP_PRI_FIRST;
    
    nf_register_net_hook(&init_net, &arp_hook);
    return 0;
}

static void __exit kguard_mitm_exit(void)
{
    nf_unregister_net_hook(&init_net, &arp_hook);
    printk(KERN_INFO "K-Guard: MITM Protection Disabled.\n");
}

module_init(kguard_mitm_init);
module_exit(kguard_mitm_exit);
