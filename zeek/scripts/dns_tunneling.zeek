# Zeek Script: Detect DNS Tunneling
# Detects DNS queries with abnormally long subdomain labels (data exfiltration indicator)

@load base/protocols/dns

module DNSTunnel;

export {
    redef enum Notice::Type += { DNS_Tunneling_Detected };
}

global query_count: table[addr] of count &default=0;
global long_label_count: table[addr] of count &default=0;

const LONG_LABEL_THRESHOLD = 30;  # characters
const QUERY_THRESHOLD = 50;       # queries per minute

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    local src = c$id$orig_h;
    query_count[src] += 1;
    
    # Check for long subdomain labels
    local labels = split_string(query, /\./);
    for (label in labels) {
        if (|labels[label]| > LONG_LABEL_THRESHOLD) {
            long_label_count[src] += 1;
            if (long_label_count[src] >= 5) {
                NOTICE([$note=DNS_Tunneling_Detected,
                        $conn=c,
                        $msg=fmt("Possible DNS tunneling from %s: %d long-label queries", src, long_label_count[src]),
                        $identifier=cat(src, "dns_tunnel")]);
                long_label_count[src] = 0;
            }
        }
    }
}

event zeek_done()
{
    # Reset counters periodically (simplified)
}
