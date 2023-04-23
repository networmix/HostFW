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

// Define VLAN header structure
struct vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

// Define the key structure for rules, containing IP, protocol, and port information
struct rule_key
{
    __u32 src_ip;
    __u32 dst_ip;
    __u8 protocol;
    __u16 src_port;
    __u16 dst_port;
};

// Define the data structure for rules, containing action and action_data (e.g., rate limit value)
struct rule_data
{
    __u8 action;
    __u32 action_data;
};

// Define the rules map (hash map) with the rule_key and rule_data structures
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct rule_key);
    __type(value, struct rule_data);
} rules_map SEC(".maps");

// Define an action data map (array) to store additional data for actions
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} action_data_map SEC(".maps");

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

    // Lookup the rule in the rules_map using the populated rule_key structure
    struct rule_data *rule = bpf_map_lookup_elem(&rules_map, &key);

    // If no matching rule is found, pass the packet
    if (!rule)
        return XDP_PASS;

    // Process the packet according to the rule's action
    switch (rule->action)
    {
    case ACCEPT:
        // If the action is ACCEPT, pass the packet
        return XDP_PASS;
    case DROP:
        // If the action is DROP, drop the packet
        return XDP_DROP;
    case RATE_LIMIT:
        // If the action is RATE_LIMIT, implement rate limiting logic using action_data_map
        // I haven't implemented this yet, but at a high-level, our algorithm would
        // use action_data_map to store packet counters and timestamps and would be implementing these steps:
        // 1.	For each incoming packet, retrieve the packet counter and timestamp from the map.
        // 2.	If more than a second passed since the last packet – update the timestamp and reset the counter to zero.
        // 3.	Increment the packet counter and compare it with the allowed number of packets per second.
        // 4.	If the rate exceeds the limit, drop the packet; otherwise, pass the packet.
        break;
    }

    // If no specific action is taken, pass the packet
    return XDP_PASS;
}

// Specify the license for the eBPF program
char _license[] SEC("license") = "GPL";
