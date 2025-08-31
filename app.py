import streamlit as st
import pandas as pd
import numpy as np
from abmap.core import load_ipdr, build_direct_edges, build_graph, top_b_parties
from abmap.correlation import infer_pairs_via_relays
from abmap.threat import label_suspicious_b
from abmap import ml as mlmod
import tempfile, os
import networkx as nx
from pyvis.network import Network
import matplotlib.pyplot as plt

# --- PAGE CONFIG AND STYLING ---
st.set_page_config(page_title="A→B Mapping (IPDR) – CyberShield", layout="wide")
st.markdown("""
    <style>
    .stApp { background-color: #0b0f19; color: #e5e7eb; }
    .stTabs [data-baseweb="tab"] { font-weight: 600; }
    </style>
""", unsafe_allow_html=True)


# --- FUNCTION DEFINITIONS ---
@st.cache_data(show_spinner="Loading IPDR data...")
def _load(path: str) -> pd.DataFrame:
    return load_ipdr(path)

def _apply_filters(df_in: pd.DataFrame, sel_start_utc, sel_end_utc, protos, ports) -> pd.DataFrame:
    q = df_in[(df_in["timestamp"] >= sel_start_utc) & (df_in["timestamp"] <= sel_end_utc)]
    if protos:
        q = q[q["protocol"].astype(str).isin(protos)]
    if ports:
        q = q[q["dst_port"].astype(int).isin(ports)]
    return q

# --- FIX IS HERE: Added 'cache_key' argument to force re-runs ---
@st.cache_data(show_spinner="Building direct edges...")
def _edges(_df: pd.DataFrame, cache_key: str) -> pd.DataFrame:
    return build_direct_edges(_df)

@st.cache_data(show_spinner="Correlating traffic for inferred pairs...")
def _infer(_df: pd.DataFrame, _min_score: float, cache_key: str) -> pd.DataFrame:
    return infer_pairs_via_relays(_df, min_score=_min_score)

@st.cache_data(show_spinner="Generating ML features...")
def _features(_edges: pd.DataFrame, cache_key: str) -> pd.DataFrame:
    return mlmod.rule_features(_edges)
# --- END FIX ---


# --- MAIN APP LAYOUT AND LOGIC ---
st.title("A→B Mapping from IPDR Logs")
st.caption("Direct mapping • Encrypted traffic correlation • Threat enrichment • ML anomalies")

# --- SIDEBAR ---
with st.sidebar:
    st.header("Data")
    up = st.file_uploader("Upload IPDR CSV", type=["csv"])
    sample_choice = st.selectbox(
        "Sample datasets",
        options=["None", "Small (5 rows)", "Regular", "Negative (no overlaps)", "Month (30 days)"],
        index=2
    )
    use_sample = (sample_choice != "None") and not bool(up)
    st.markdown("**CSV schema:** `timestamp, src_ip, ...`")
    st.divider()
    st.header("Filters")
    min_overlap = st.slider("Correlation sensitivity (min score)", 0.5, 0.95, 0.7, 0.05)
    contamination = st.slider("Anomaly proportion (ML)", 0.01, 0.2, 0.05, 0.01)
    show_inferred = st.toggle("Show inferred A↔B edges", value=True)
    min_sessions = st.number_input("Min sessions per edge", min_value=1, value=1, step=1)
    min_total_bytes = st.number_input("Min total bytes per edge", min_value=0, value=0, step=1000)
    node_query = st.text_input("Search node (IP)")

# --- DATA LOADING ---
csv_path = None
try:
    if use_sample:
        mapping = {
            "Small (5 rows)": "data/sample_small.csv",
            "Regular": "data/sample_ipdr.csv",
            "Negative (no overlaps)": "data/sample_ipdr_negative.csv",
            "Month (30 days)": "data/sample_ipdr_month.csv",
        }
        csv_path = mapping.get(sample_choice)
        if not csv_path or not os.path.exists(csv_path):
             st.warning(f"Sample file not found: {csv_path}. Please generate it.")
             st.stop()
    elif up:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as t:
            t.write(up.read())
            csv_path = t.name
    else:
        st.info("Upload a CSV or select a sample dataset to begin.")
        st.stop()

    df = _load(csv_path)

except Exception as e:
    st.error(f"Failed to load CSV: {e}")
    st.stop()

# --- UI EXPANDERS FOR OVERVIEW AND FILTERING ---
with st.expander("Dataset overview", expanded=True):
    c1, c2, c3 = st.columns(3)
    with c1: st.metric("Rows", f"{len(df):,}"); st.metric("Unique A-parties", df["src_ip"].nunique())
    with c2: st.metric("Time range", f"{df['timestamp'].min()} → {df['timestamp'].max()}"); st.metric("Unique B-parties", df["dst_ip"].nunique())
    with c3: st.metric("Protocols", ", ".join(sorted(df["protocol"].astype(str).unique().tolist())[:5])); st.metric("Ports", f"{df['dst_port'].nunique()} distinct")

with st.expander("Refine dataset", expanded=False):
    tmin, tmax = df["timestamp"].min().to_pydatetime(), df["timestamp"].max().to_pydatetime()
    sel = st.slider("Time window", value=(tmin, tmax), min_value=tmin, max_value=tmax)
    sel_start_utc = pd.to_datetime(sel[0], utc=True)
    sel_end_utc = pd.to_datetime(sel[1], utc=True)
    protos = st.multiselect("Protocols", sorted(df["protocol"].astype(str).unique().tolist()))
    ports = st.multiselect("Destination ports", sorted(df["dst_port"].astype(int).unique().tolist()))

# --- ANALYSIS PIPELINE ---
df_f = _apply_filters(df, sel_start_utc, sel_end_utc, protos, ports)

# --- FIX IS HERE: Pass 'csv_path' as the cache_key ---
edges = _edges(df_f, cache_key=csv_path)
edges = edges[(edges["sessions"] >= min_sessions) & (edges["total_bytes"] >= min_total_bytes)]

if show_inferred:
    inferred = _infer(df_f, min_overlap, cache_key=csv_path)
else:
    inferred = pd.DataFrame(columns=["a_ip", "b_ip", "relay_ip", "score", "overlaps"])

sus_b = label_suspicious_b(edges)
feat = _features(edges, cache_key=csv_path)
anom = mlmod.isolation_forest_anomalies(feat, contamination=contamination)
anom_nodes = set(anom[anom["is_anomaly"]]["node"].tolist())
# --- END FIX ---

# --- DISPLAY RESULTS ---
col1, col2 = st.columns([2, 1])
with col1:
    st.subheader("Interactive Graph")
    if len(edges) > 0 or len(inferred) > 0:
        G = build_graph(edges, inferred_pairs=inferred if show_inferred else None, suspicious_b=sus_b, anomalous_nodes=anom_nodes, highlight_node=node_query if node_query else None)
        net = Network(height="700px", width="100%", notebook=False, directed=False, bgcolor="#0b0f19", cdn_resources='in_line')
        for n, data in G.nodes(data=True): net.add_node(n, label=n, color=data.get("color", "gray"), shape=data.get("shape", "dot"), size=data.get("size", 12))
        for u, v, data in G.edges(data=True):
            color = {"direct": "#16a34a", "inferred": "#f97316"}.get(data.get("edge_type"), "#64748b")
            title = ", ".join(f"{k}: {v}" for k, v in data.items() if k not in ["edge_type"])
            net.add_edge(u, v, color=color, title=title, width=2)
        try:
            html = net.generate_html()
            st.components.v1.html(html, height=720, scrolling=True)
            st.download_button("Download graph HTML", data=html, file_name="graph.html", mime="text/html")
        except Exception as e:
            st.error(f"Could not generate graph. Error: {e}")
    else:
        st.info("No edges to display for the current filter settings.")

with col2:
    st.subheader("Top B-parties")
    topb = top_b_parties(edges, n=12)
    st.dataframe(topb, use_container_width=True)
    st.subheader("B-party drill-down")
    b_options = sorted(edges["dst_ip"].unique().tolist())
    sel_b = st.selectbox("Select B-party", options=[""] + b_options)
    if sel_b:
        be = edges[edges["dst_ip"] == sel_b]; partners = be.groupby("src_ip", as_index=False).agg(sessions=("sessions", "sum"), total_bytes=("total_bytes", "sum")).sort_values(["sessions", "total_bytes"], ascending=[False, False]); st.caption("Partners (A→selected B)"); st.dataframe(partners, use_container_width=True)
        recent = df_f[df_f["dst_ip"] == sel_b].sort_values("timestamp", ascending=False).head(100); st.caption("Recent sessions to selected B"); st.dataframe(recent, use_container_width=True)
    st.subheader("Inferred A↔B via same relay")
    if len(inferred) == 0: st.info("No strong overlaps found.")
    else: st.dataframe(inferred, use_container_width=True)
    st.subheader("Anomalous Nodes (ML)")
    st.dataframe(anom[anom["is_anomaly"]].head(15), use_container_width=True)

st.divider()
st.caption("Legend: Green=direct, Orange=inferred; Red=suspicious; Purple ring=anomaly")

