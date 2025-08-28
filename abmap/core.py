from __future__ import annotations
import pandas as pd
import numpy as np
import networkx as nx
from typing import List, Dict, Tuple

REQUIRED_COLS = [
    "timestamp","src_ip","src_port","dst_ip","dst_port","protocol",
    "bytes_sent","bytes_received","duration_ms","session_id"
]

def load_ipdr(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    missing = [c for c in REQUIRED_COLS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors="coerce").fillna(0).astype(int)
    df["bytes_received"] = pd.to_numeric(df["bytes_received"], errors="coerce").fillna(0).astype(int)
    df["duration_ms"] = pd.to_numeric(df["duration_ms"], errors="coerce").fillna(0).astype(int)
    # Derive some helper columns
    df["total_bytes"] = df["bytes_sent"] + df["bytes_received"]
    return df.sort_values("timestamp")

def build_direct_edges(df: pd.DataFrame) -> pd.DataFrame:
    grp = df.groupby(["src_ip","dst_ip"], as_index=False).agg(
        sessions=("session_id","nunique"),
        total_bytes=("total_bytes","sum"),
        avg_duration_ms=("duration_ms","mean"),
        first_seen=("timestamp","min"),
        last_seen=("timestamp","max")
    )
    grp["edge_type"] = "direct"
    return grp

def top_b_parties(edges: pd.DataFrame, n:int=10) -> pd.DataFrame:
    return edges.sort_values(["sessions","total_bytes"], ascending=[False,False]).head(n)

def build_graph(
                direct_edges: pd.DataFrame,
                inferred_pairs: pd.DataFrame|None=None,
                suspicious_b: set[str]|None=None,
                anomalous_nodes: set[str]|None=None,
                highlight_node: str|None=None
                ) -> nx.Graph:
    G = nx.Graph()
    suspicious_b = suspicious_b or set()
    anomalous_nodes = anomalous_nodes or set()
    # Nodes
    for _, row in direct_edges.iterrows():
        a = row["src_ip"]; b = row["dst_ip"]
        # A node
        a_color = "#60a5fa"  # blue
        a_color_obj = {"background": a_color, "border": "#a855f7" if a in anomalous_nodes else a_color}
        G.add_node(a, node_type="A", color=a_color_obj, shape="dot")
        # B node
        b_color = "#ef4444" if b in suspicious_b else "#22c55e"
        b_color_obj = {"background": b_color, "border": "#a855f7" if b in anomalous_nodes else b_color}
        G.add_node(b, node_type="B", color=b_color_obj, shape="dot")
        # Edge
        G.add_edge(a,b, edge_type="direct",
                   weight=float(row["sessions"]),
                   sessions=int(row["sessions"]),
                   total_bytes=int(row["total_bytes"]))
    # Inferred A<->A edges
    if inferred_pairs is not None and len(inferred_pairs):
        for _, r in inferred_pairs.iterrows():
            a = r["a_ip"]; b = r["b_ip"]
            a_color_obj = {"background": "#60a5fa", "border": "#a855f7" if a in anomalous_nodes else "#60a5fa"}
            b_color_obj = {"background": "#60a5fa", "border": "#a855f7" if b in anomalous_nodes else "#60a5fa"}
            G.add_node(a, node_type="A", color=a_color_obj, shape="dot")
            G.add_node(b, node_type="A", color=b_color_obj, shape="dot")
            G.add_edge(a,b, edge_type="inferred",
                       weight=float(r["score"]),
                       score=float(r["score"]),
                       relay=r.get("relay_ip","?"),
                       overlaps=int(r.get("overlaps",1)))
    # Optional highlighting
    if highlight_node and highlight_node in G:
        # increase size for the node and its neighbors
        for n in [highlight_node] + list(G.neighbors(highlight_node)):
            if n in G.nodes:
                G.nodes[n]["size"] = 25 if n == highlight_node else 18
    return G
