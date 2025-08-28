from __future__ import annotations
import pandas as pd
import numpy as np

def rule_features(edges: pd.DataFrame) -> pd.DataFrame:
    # Build per-node features from edges
    # degree, total_bytes, num_partners
    features = {}
    for _, r in edges.iterrows():
        a = r["src_ip"]; b = r["dst_ip"]
        features.setdefault(a, {"node": a, "role":"A", "sessions":0, "bytes":0, "partners":set()})
        features.setdefault(b, {"node": b, "role":"B", "sessions":0, "bytes":0, "partners":set()})
        features[a]["sessions"] += r["sessions"]; features[a]["bytes"] += r["total_bytes"]; features[a]["partners"].add(b)
        features[b]["sessions"] += r["sessions"]; features[b]["bytes"] += r["total_bytes"]; features[b]["partners"].add(a)
    rows = []
    for node, d in features.items():
        rows.append({
            "node": node,
            "role": d["role"],
            "sessions": d["sessions"],
            "bytes": d["bytes"],
            "n_partners": len(d["partners"])
        })
    return pd.DataFrame(rows)

def isolation_forest_anomalies(df_features: pd.DataFrame, contamination: float = 0.05):
    try:
        from sklearn.ensemble import IsolationForest
    except Exception:
        # Fallback: simple z-score on n_partners and bytes
        feat = df_features[["n_partners","bytes"]].astype(float)
        z = (feat - feat.mean())/feat.std(ddof=0)
        score = -z.abs().mean(axis=1)
        df = df_features.copy()
        df["anomaly_score"] = score
        df["is_anomaly"] = score < score.quantile(contamination)
        return df.sort_values("anomaly_score")
    clf = IsolationForest(contamination=contamination, random_state=42)
    X = df_features[["sessions","bytes","n_partners"]].astype(float)
    clf.fit(X)
    scores = clf.decision_function(X)
    preds = clf.predict(X)  # -1 anomaly, 1 normal
    out = df_features.copy()
    out["anomaly_score"] = scores
    out["is_anomaly"] = preds==-1
    return out.sort_values("anomaly_score")
