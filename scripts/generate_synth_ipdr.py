import pandas as pd
from datetime import datetime, timedelta
import random

random.seed(7)

A_PARTIES = ["192.0.2.10","192.0.2.20","192.0.2.30","192.0.2.40"]
B_NORMAL  = ["93.184.216.34","203.0.113.10","203.0.113.11"]
VPNs      = ["198.51.100.5","198.51.100.6"]
B_BAD     = ["203.0.113.77"]

def gen_session(ts, src, dst, port, proto, dur_s, up_kb, down_kb, sid):
    return {
        "timestamp": ts.isoformat(),
        "src_ip": src, "src_port": random.randint(1024,65535),
        "dst_ip": dst, "dst_port": port, "protocol": proto,
        "bytes_sent": int(up_kb*1024), "bytes_received": int(down_kb*1024),
        "duration_ms": int(dur_s*1000), "session_id": sid
    }

def main(n=240):
    rows = []
    t0 = datetime(2025,8,1,10,0,0)
    sid = 1

    # Regular web
    for _ in range(n//2):
        src = random.choice(A_PARTIES)
        dst = random.choice(B_NORMAL)
        ts = t0 + timedelta(seconds=random.randint(0,3600))
        dur = random.randint(1,30)
        up = random.uniform(10,200); down = random.uniform(50,1000)
        rows.append(gen_session(ts, src, dst, 443, "TCP", dur, up, down, sid)); sid+=1

    # A1 and A2 talk via VPN1 with overlapping times
    for i in range(5):
        tsA = t0 + timedelta(minutes=30+i*5)
        tsB = tsA + timedelta(seconds=random.randint(5,20))
        dur = random.randint(200,400)
        rows.append(gen_session(tsA, A_PARTIES[0], VPNs[0], 443, "UDP", dur, 600+50*i, 600+60*i, sid)); sid+=1
        rows.append(gen_session(tsB, A_PARTIES[1], VPNs[0], 443, "UDP", dur-10, 590+50*i, 610+60*i, sid)); sid+=1

    # Some noise via VPN2 with no overlap
    for i in range(6):
        ts = t0 + timedelta(minutes=10*i)
        src = random.choice(A_PARTIES[2:])
        rows.append(gen_session(ts, src, VPNs[1], 443, "UDP", random.randint(60,120),
                                random.uniform(50,120), random.uniform(60,130), sid)); sid+=1

    # Suspicious server activity from A3
    for i in range(4):
        ts = t0 + timedelta(minutes=15*i + 7)
        rows.append(gen_session(ts, A_PARTIES[2], B_BAD[0], 8443, "TCP", random.randint(120,240),
                                random.uniform(400,700), random.uniform(50,80), sid)); sid+=1

    df = pd.DataFrame(rows).sort_values("timestamp")
    df.to_csv("data/sample_ipdr.csv", index=False)
    print("Wrote data/sample_ipdr.csv with", len(df), "rows.")

if __name__ == "__main__":
    main()
