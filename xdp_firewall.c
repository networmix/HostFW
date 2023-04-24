// Include necessary headers for eBPF, network protocols, and helpers
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define constants for rule actions
#define ACCEPT 0
#define DROP 1
#define RATE_LIMIT 2

// Define constant for maximum number of rules
#define MAX_RULES 128

// Define VLAN header structure
struct vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

// Define the data structure for firewall rules.
// This structure will be used as the value in the rules_map.
// __attribute__((packed)) is used to ensure that the structure is packed
// and does not contain any padding between fields.
// This is necessary to ensure that the structure is the same size as the
// the one in the user space program.
struct __attribute__((packed)) rule_data
{
    __u32 src_ip;   // Source IP address
    __u32 dst_ip;   // Destination IP address
    __u8 protocol;  // IP Protocol (e.g., TCP is 6, UDP is 17, ICMP is 1)
    __u16 src_port; // Source port for TCP/UDP
    __u16 dst_port; // Destination port for TCP/UDP
    __u8 action;    // Action to take (ACCEPT, DROP, or RATE_LIMIT)
    __u32 action_data;
};

// Define the data structure used to compare packets against firewall rules.
struct rule_key
{
    __u32 src_ip;   // Source IP address
    __u32 dst_ip;   // Destination IP address
    __u8 protocol;  // IP Protocol (e.g., TCP is 6, UDP is 17, ICMP is 1)
    __u16 src_port; // Source port for TCP/UDP
    __u16 dst_port; // Destination port for TCP/UDP
};

// Define the rules map
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct rule_data);
} rules_map SEC(".maps");

// Function to parse the packet and fill in the rule_key structure
static int parse_packet(void *data, void *data_end, struct rule_key *key)
{
    // Parse Ethernet header
    struct ethhdr *eth = data;

    // Check if the Ethernet header is within the packet boundaries
    if ((void *)eth + sizeof(*eth) > data_end)
        return 0;

    // Extract Ethernet protocol and offset
    __u16 eth_proto = eth->h_proto;
    __u16 offset = sizeof(*eth);

    // Check for and parse VLAN header if present
    if (eth_proto == bpf_htons(ETH_P_8021Q))
    {
        struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);

        // Check if the VLAN header is within the packet boundaries
        if ((void *)vlan + sizeof(*vlan) > data_end)
            return 0;

        // Update Ethernet protocol and offset
        eth_proto = vlan->h_vlan_encapsulated_proto;
        offset += sizeof(*vlan);
    }

    // Only proceed if the packet is an IPv4 packet
    if (eth_proto != bpf_htons(ETH_P_IP))
        return 0;

    // Parse IP header
    struct iphdr *ip = data + offset;

    // Check if the IP header is within the packet boundaries
    if ((void *)ip + sizeof(*ip) > data_end)
        return 0;

    // Fill in the rule_key structure with IP and protocol information
    key->src_ip = ip->saddr;
    key->dst_ip = ip->daddr;
    key->protocol = ip->protocol;

    // Parse transport layer header (UDP or TCP) and fill in the rule_key structure with port information
    if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)udp + sizeof(*udp) > data_end)
            return 0;

        key->src_port = udp->source;
        key->dst_port = udp->dest;
    }
    else if (ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return 0;

        key->src_port = tcp->source;
        key->dst_port = tcp->dest;
    }
    else
    {
        key->src_port = 0;
        key->dst_port = 0;
    }

    return 1;
}

/**
 * Helper function to check if a given rule matches the packet.
 * The function compares the source IP, destination IP, protocol, source port, and destination port
 * of the packet (represented by a rule_key) against the corresponding fields of a rule_data object.
 * If a rule field has a zero value, it is considered a wildcard and will match any value in the corresponding
 * field of the packet. Otherwise, the field must match the corresponding packet field exactly.
 *
 * @param key Pointer to a rule_key structure representing the packet information.
 * @param rule Pointer to a rule_data structure representing the firewall rule.
 * @return 1 if the rule matches the packet, 0 otherwise.
 */
static int rule_matches(struct rule_key *key, struct rule_data *rule)
{
    return ((rule->src_ip == 0 || rule->src_ip == key->src_ip) &&
            (rule->dst_ip == 0 || rule->dst_ip == key->dst_ip) &&
            (rule->protocol == key->protocol) &&
            (rule->src_port == 0 || rule->src_port == key->src_port) &&
            (rule->dst_port == 0 || rule->dst_port == key->dst_port));
}

// Main XDP program
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    // Get pointers to the packet data and data_end
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Initialize rule_key structure
    struct rule_key key = {};

    // Call parse_packet to fill in the rule_key structure, and return XDP_PASS if parsing fails
    if (!parse_packet(data, data_end, &key))
        return XDP_PASS;

    // Loop over all rules in the map and check if the rule matches the packet
    // Note that we use two variables here: rule_idx and i. Variable i is used to iterate over the map
    // and bound the loop to MAX_RULES. Variable rule_idx is used to lookup the map.
    // Othervise, BPF validation would fail after detecting a potential infinite loop.
    __u32 rule_idx = 0;
    struct rule_data *rule;
    for (__u32 i = 0; i < MAX_RULES; i++)
    {
        rule = bpf_map_lookup_elem(&rules_map, &rule_idx);
        if (rule == NULL)
        {
            break;
        }
        // If the rule matches the packet, process it according to the rule's action
        if (rule_matches(&key, rule))
        {
            switch (rule->action)
            {
            case ACCEPT:
                // If the action is ACCEPT, pass the packet
                return XDP_PASS;
            case DROP:
                // If the action is DROP, drop the packet
                return XDP_DROP;
            case RATE_LIMIT:
                // If the action is RATE_LIMIT, implement rate limiting logic.
                // I haven't implemented this yet, but at a high-level, our algorithm would
                // use action_data_map to store packet counters and timestamps and would be implementing these steps:
                // 1.	For each incoming packet, retrieve the packet counter and timestamp from the map.
                // 2.	If more than a second passed since the last packet – update the timestamp and reset the counter to zero.
                // 3.	Increment the packet counter and compare it with the allowed number of packets per second.
                // 4.	If the rate exceeds the limit, drop the packet; otherwise, pass the packet.

                return XDP_PASS;
            }
        }
        rule_idx++;
    }
    // If no specific action is taken, pass the packet
    return XDP_PASS;
}
// Specify the license for the eBPF program
char _license[] SEC("license") = "GPL";
