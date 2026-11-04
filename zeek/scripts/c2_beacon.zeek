# Zeek Script: Detect HTTP C2 Beaconing
# Detects regular HTTP GET requests to the same URI at consistent intervals

@load base/protocols/http

module C2Beacon;

export {
    redef enum Notice::Type += { C2_Beacon_Detected };
}

global beacon_tracker: table[addr, string] of count &default=0;
global last_seen: table[addr, string] of time &default=network_time();

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    if (method == "GET" && /\/api\// in original_URI) {
        local src = c$id$orig_h;
        local key = original_URI;
        local now = network_time();
        
        if (src in beacon_tracker && key in beacon_tracker[src]) {
            local interval = now - last_seen[src, key];
            if (interval < 5min && interval > 10sec) {
                beacon_tracker[src, key] += 1;
                if (beacon_tracker[src, key] >= 5) {
                    NOTICE([$note=C2_Beacon_Detected,
                            $conn=c,
                            $msg=fmt("Possible C2 beaconing from %s to %s", src, original_URI),
                            $identifier=cat(src, original_URI)]);
                    beacon_tracker[src, key] = 0;
                }
            }
        } else {
            beacon_tracker[src, key] = 1;
        }
        last_seen[src, key] = now;
    }
}