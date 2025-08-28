import pandas as pd
from datetime import datetime, timedelta
import random

random.seed(11)

A_PARTIES = [f"192.0.2.{i}" for i in [50,60,70,80]]
B_NORMAL  = ["93.184.216.34","203.0.113.10","203.0.113.11","203.0.113.12"]
VPNs      = ["198.51.100.9","198.51.100.10"]

def gen_session(ts, src, dst, port, proto, dur_s, up_kb, down_kb, sid):
    return {
        "timestamp": ts.isoformat(),
        "src_ip": src, "src_port": random.randint(1024,65535),
        "dst_ip": dst, "dst_port": port, "protocol": proto,
        "bytes_sent": int(up_kb*1024), "bytes_received": int(down_kb*1024),
        "duration_ms": int(dur_s*1000), "session_id": sid
    }

def main(n=800):
    rows = []
    t0 = datetime(2025,8,2,9,0,0)
    sid = 1

    # Normal web, more noise, no overlapping pairs on same VPN window
    for _ in range(n//2):
        src = random.choice(A_PARTIES)
        dst = random.choice(B_NORMAL)
        ts = t0 + timedelta(seconds=random.randint(0,5400))
        dur = random.randint(5,60)
        up = random.uniform(5,50); down = random.uniform(20,400)
        rows.append(gen_session(ts, src, dst, 443, "TCP", dur, up, down, sid)); sid+=1

    # VPN usage but staggered so no overlaps between different As
    for src in A_PARTIES:
        for i in range(6):
            ts = t0 + timedelta(minutes=5*i + random.randint(0,3))
            rows.append(gen_session(ts, src, random.choice(VPNs), 443, "UDP",
                                    random.randint(120,240), random.uniform(80,160), random.uniform(80,160), sid)); sid+=1

    df = pd.DataFrame(rows).sort_values("timestamp")
    df.to_csv("data/sample_ipdr_negative.csv", index=False)
    print("Wrote data/sample_ipdr_negative.csv with", len(df), "rows.")

if __name__ == "__main__":
    main()


