from __future__ import annotations
import pandas as pd
import numpy as np
from itertools import combinations

# Heuristic: treat a destination as a relay/VPN candidate if it sees many distinct src_ip
def candidate_relays(df: pd.DataFrame, min_clients:int=2) -> pd.Series:
    client_counts = df.groupby("dst_ip")["src_ip"].nunique()
    return client_counts[client_counts>=min_clients].index

def time_overlap(a_start, a_end, b_start, b_end) -> float:
    latest_start = max(a_start, b_start)
    earliest_end = min(a_end, b_end)
    overlap = (earliest_end - latest_start).total_seconds()
    if overlap <= 0: return 0.0
    denom = (max(a_end, b_end) - min(a_start, b_start)).total_seconds()
    return overlap/denom if denom>0 else 0.0

def bytes_similarity(a_sent, a_recv, b_sent, b_recv) -> float:
    # Compare magnitude patterns (not exact equality). Use cosine-like measure.
    va = np.array([a_sent, a_recv], dtype=float)
    vb = np.array([b_sent, b_recv], dtype=float)
    if np.linalg.norm(va)==0 or np.linalg.norm(vb)==0:
        return 0.0
    cos = float(np.dot(va, vb) / (np.linalg.norm(va)*np.linalg.norm(vb)))
    # Normalize from [-1,1] to [0,1]
    return (cos+1)/2

def infer_pairs_via_relays(df: pd.DataFrame,
                           window_seconds:int=90,
                           min_score:float=0.7) -> pd.DataFrame:
    rows = []
    for relay in candidate_relays(df, min_clients=2):
        sub = df[df["dst_ip"]==relay].copy()
        # derive session windows per src_ip using session_id groups
        sub["start"] = sub["timestamp"]
        sub["end"] = sub["timestamp"] + pd.to_timedelta(sub["duration_ms"], unit="ms")
        # Pad window to allow clock jitters
        sub["start"] -= pd.to_timedelta(window_seconds//2, unit="s")
        sub["end"]   += pd.to_timedelta(window_seconds//2, unit="s")
        by_src = list(sub.groupby("src_ip"))
        for (a_ip, a_df), (b_ip, b_df) in combinations(by_src, 2):
            overlaps = 0
            best_score = 0.0
            for _, ar in a_df.iterrows():
                for _, br in b_df.iterrows():
                    tovl = time_overlap(ar["start"], ar["end"], br["start"], br["end"])
                    if tovl <= 0: 
                        continue
                    bs = bytes_similarity(ar["bytes_sent"], ar["bytes_received"],
                                          br["bytes_sent"], br["bytes_received"])
                    score = 0.6*tovl + 0.4*bs
                    best_score = max(best_score, score)
                    if score >= min_score:
                        overlaps += 1
            if best_score >= min_score and overlaps>0:
                rows.append({
                    "a_ip": a_ip, "b_ip": b_ip, "relay_ip": relay,
                    "score": round(float(best_score),3), "overlaps": int(overlaps)
                })
    return pd.DataFrame(rows).drop_duplicates()
