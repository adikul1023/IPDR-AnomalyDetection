import pandas as pd
from datetime import datetime, timedelta
import random
import math

random.seed(21)

# A-parties (clients)
A_PARTIES = [f"192.0.2.{i}" for i in range(10, 60, 5)]
# Common B services and a few suspicious
B_NORMAL  = [
    "93.184.216.34","203.0.113.10","203.0.113.11","203.0.113.12",
    "151.101.1.69","142.250.72.238","151.101.193.69"
]
VPNs      = ["198.51.100.5","198.51.100.6","198.51.100.7"]
B_BAD     = ["203.0.113.77","198.51.100.66"]

def gen_session(ts, src, dst, port, proto, dur_s, up_kb, down_kb, sid):
    return {
        "timestamp": ts.isoformat(),
        "src_ip": src, "src_port": random.randint(1024,65535),
        "dst_ip": dst, "dst_port": port, "protocol": proto,
        "bytes_sent": int(up_kb*1024), "bytes_received": int(down_kb*1024),
        "duration_ms": int(dur_s*1000), "session_id": sid
    }

def diurnal_multiplier(dt: datetime) -> float:
    # Peak during business hours (9am-7pm local), lower at night
    hour = dt.hour
    base = 0.5 + 0.5*math.sin((hour-9)/24*2*math.pi)
    return max(0.2, base)

def main(days=30, base_events_per_day=800):
    rows = []
    t0 = datetime(2025,7,1,0,0,0)
    sid = 1

    for d in range(days):
        day_start = t0 + timedelta(days=d)
        mult = random.uniform(0.8,1.2)
        total = int(base_events_per_day * mult)
        for _ in range(total):
            src = random.choice(A_PARTIES)
            # choose an hour with diurnal pattern
            rand_sec = random.randint(0, 86400-1)
            ts = day_start + timedelta(seconds=rand_sec)
            # apply light diurnal bias by re-rolling some events to business hours
            if random.random() > diurnal_multiplier(ts):
                # nudge toward 9am-7pm
                ts = day_start + timedelta(hours=random.randint(9,19), minutes=random.randint(0,59), seconds=random.randint(0,59))

            # Normal web traffic
            if random.random() < 0.88:
                dst = random.choice(B_NORMAL)
                port = 443
                proto = "TCP"
                dur = random.randint(2,120)
                up = random.uniform(10,300)
                down = random.uniform(50,2000)
                rows.append(gen_session(ts, src, dst, port, proto, dur, up, down, sid)); sid+=1
                continue

            # VPN sessions
            if random.random() < 0.10:
                dst = random.choice(VPNs)
                port = 443
                proto = "UDP"
                dur = random.randint(120,1200)
                up = random.uniform(200,1500)
                down = random.uniform(200,1500)
                rows.append(gen_session(ts, src, dst, port, proto, dur, up, down, sid)); sid+=1
                continue

            # Suspicious server communications
            dst = random.choice(B_BAD)
            port = random.choice([8443, 8080])
            proto = "TCP"
            dur = random.randint(60,900)
            up = random.uniform(300,2000)
            down = random.uniform(20,200)
            rows.append(gen_session(ts, src, dst, port, proto, dur, up, down, sid)); sid+=1

    # Add correlated VPN overlaps for a handful of A-pairs on the same day
    for d in range(0, days, 3):
        day_start = t0 + timedelta(days=d)
        for _ in range(3):
            a1, a2 = random.sample(A_PARTIES, 2)
            vpn = random.choice(VPNs)
            base_ts = day_start + timedelta(hours=random.randint(10,18), minutes=random.randint(0,59))
            for i in range(3):
                ts1 = base_ts + timedelta(minutes=i*10)
                ts2 = ts1 + timedelta(seconds=random.randint(5,40))
                dur = random.randint(300,900)
                rows.append(gen_session(ts1, a1, vpn, 443, "UDP", dur, 800+30*i, 820+35*i, sid)); sid+=1
                rows.append(gen_session(ts2, a2, vpn, 443, "UDP", dur-30, 780+28*i, 840+33*i, sid)); sid+=1

    df = pd.DataFrame(rows).sort_values("timestamp")
    df.to_csv("data/sample_ipdr_month.csv", index=False)
    print("Wrote data/sample_ipdr_month.csv with", len(df), "rows.")

if __name__ == "__main__":
    main()


