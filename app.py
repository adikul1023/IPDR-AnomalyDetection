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

st.set_page_config(page_title="A→B Mapping (IPDR) – CyberShield", layout="wide")
st.markdown("""
    <style>
    .stApp { background-color: #0b0f19; color: #e5e7eb; }
    .stTabs [data-baseweb="tab"] { font-weight: 600; }
    </style>
""", unsafe_allow_html=True)

st.title("A→B Mapping from IPDR Logs")
st.caption("Direct mapping • Encrypted traffic correlation • Threat enrichment • ML anomalies")

with st.sidebar:
    st.header("Data")
    up = st.file_uploader("Upload IPDR CSV", type=["csv"])
    sample_choice = st.selectbox(
        "Sample datasets",
        options=["None","Small (5 rows)","Regular","Negative (no overlaps)","Month (30 days)"] ,
        index=2
    )
    use_sample = (sample_choice != "None") and not bool(up)
    st.markdown("**CSV schema:** `timestamp, src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent, bytes_received, duration_ms, session_id`")
    st.divider()
    st.header("Filters")
    min_overlap = st.slider("Correlation sensitivity (min score)", 0.5, 0.95, 0.7, 0.05)
    contamination = st.slider("Anomaly proportion (ML)", 0.01, 0.2, 0.05, 0.01)
    show_inferred = st.toggle("Show inferred A↔B edges", value=True)
    min_sessions = st.number_input("Min sessions per edge", min_value=1, value=1, step=1)
    min_total_bytes = st.number_input("Min total bytes per edge", min_value=0, value=0, step=1000)
    node_query = st.text_input("Search node (IP)")

@st.cache_data(show_spinner=False)
def _load(path: str) -> pd.DataFrame:
    return load_ipdr(path)

try:
    if use_sample:
        mapping = {
            "Small (5 rows)": os.path.join("data","sample_small.csv"),
            "Regular": os.path.join("data","sample_ipdr.csv"),
            "Negative (no overlaps)": os.path.join("data","sample_ipdr_negative.csv"),
            "Month (30 days)": os.path.join("data","sample_ipdr_month.csv"),
        }
        csv_path = mapping.get(sample_choice, os.path.join("data","sample_ipdr.csv"))
        # Auto-generate if missing for supported samples
        if not os.path.exists(csv_path):
            try:
                if sample_choice == "Negative (no overlaps)":
                    from scripts.generate_synth_ipdr_negative import main as gen_neg
                    gen_neg()
                elif sample_choice == "Month (30 days)":
                    from scripts.generate_synth_ipdr_month import main as gen_month
                    gen_month()
            except Exception as _:
                pass
    else:
        if up:
            t = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
            t.write(up.read()); t.flush()
            csv_path = t.name
        else:
            st.stop()
    df = _load(csv_path)
    st.toast(f"Loaded {len(df):,} rows", icon="✅")
except Exception as e:
    st.error(f"Failed to load CSV: {e}")
    st.stop()

with st.expander("Dataset overview", expanded=True):
    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Rows", f"{len(df):,}")
        st.metric("Unique A-parties", df["src_ip"].nunique())
    with c2:
        st.metric("Time range", f"{df['timestamp'].min()} → {df['timestamp'].max()}")
        st.metric("Unique B-parties", df["dst_ip"].nunique())
    with c3:
        st.metric("Protocols", ", ".join(sorted(df["protocol"].astype(str).unique().tolist())[:5]))
        st.metric("Ports", f"{df['dst_port'].nunique()} distinct")
    # Small histograms
    fig, axes = plt.subplots(1,2, figsize=(8,2))
    df["protocol"].value_counts().plot(kind="bar", ax=axes[0], color="#93c5fd")
    axes[0].set_title("Protocols")
    df["dst_port"].value_counts().head(10).plot(kind="bar", ax=axes[1], color="#86efac")
    axes[1].set_title("Top 10 dst ports")
    st.pyplot(fig, clear_figure=True)

# Time-series panel (hourly traffic for current filters)
with st.expander("Traffic by hour", expanded=False):
    if len(df) > 0:
        ts_df = df.copy()
        ts_df["total_bytes"] = ts_df["bytes_sent"] + ts_df["bytes_received"]
        ts_df = ts_df.set_index("timestamp").sort_index()
        hourly = ts_df["total_bytes"].resample("1H").sum().reset_index()
        st.line_chart(hourly, x="timestamp", y="total_bytes")
    else:
        st.info("No data to plot.")

# Time and attribute filters
with st.expander("Refine dataset", expanded=False):
    tmin_ts, tmax_ts = df["timestamp"].min(), df["timestamp"].max()
    # Convert to native Python datetimes for Streamlit slider
    tmin = tmin_ts.to_pydatetime()
    tmax = tmax_ts.to_pydatetime()
    sel = st.slider("Time window", value=(tmin, tmax), min_value=tmin, max_value=tmax)
    # Convert selection back to UTC pandas Timestamps for filtering
    sel_start_utc = pd.to_datetime(sel[0], utc=True)
    sel_end_utc = pd.to_datetime(sel[1], utc=True)
    protos = st.multiselect("Protocols", sorted(df["protocol"].astype(str).unique().tolist()))
    ports = st.multiselect("Destination ports", sorted(df["dst_port"].astype(int).unique().tolist()))

def _apply_filters(df_in: pd.DataFrame) -> pd.DataFrame:
    q = df_in[(df_in["timestamp"]>=sel_start_utc) & (df_in["timestamp"]<=sel_end_utc)]
    if protos:
        q = q[q["protocol"].astype(str).isin(protos)]
    if ports:
        q = q[q["dst_port"].astype(int).isin(ports)]
    return q

df_f = _apply_filters(df)

@st.cache_data(show_spinner=False)
def _edges(_df: pd.DataFrame) -> pd.DataFrame:
    return build_direct_edges(_df)

edges = _edges(df_f)
edges = edges[(edges["sessions"]>=min_sessions) & (edges["total_bytes"]>=min_total_bytes)]

@st.cache_data(show_spinner=False)
def _infer(_df: pd.DataFrame, _min_score: float) -> pd.DataFrame:
    return infer_pairs_via_relays(_df, min_score=_min_score)

# Correlation (VPN/E2E inference)
inferred = _infer(df_f, min_overlap) if show_inferred else pd.DataFrame(columns=["a_ip","b_ip","relay_ip","score","overlaps"])

# Threat enrichment
sus_b = label_suspicious_b(edges)

@st.cache_data(show_spinner=False)
def _features(_edges: pd.DataFrame) -> pd.DataFrame:
    return mlmod.rule_features(_edges)

feat = _features(edges)
anom = mlmod.isolation_forest_anomalies(feat, contamination=contamination)
anom_nodes = set(anom[anom["is_anomaly"]]["node"].tolist())

col1, col2 = st.columns([2,1])
with col1:
    st.subheader("Interactive Graph")
    G = build_graph(edges, inferred_pairs=inferred if show_inferred else None, suspicious_b=sus_b, anomalous_nodes=anom_nodes, highlight_node=node_query if node_query else None)
    net = Network(height="700px", width="100%", notebook=False, directed=False, bgcolor="#0b0f19")
    for n, data in G.nodes(data=True):
        net.add_node(n, label=n, color=data.get("color","gray"), shape=data.get("shape","dot"), size=data.get("size", 12))
    for u,v,data in G.edges(data=True):
        color = {"direct":"#16a34a", "inferred":"#f97316"}.get(data.get("edge_type"), "#64748b")
        title = ", ".join(f"{k}: {v}" for k,v in data.items() if k not in ["edge_type"])
        net.add_edge(u,v, color=color, title=title, width=2)
    out_html = os.path.join(tempfile.gettempdir(), "graph.html")
    net.write_html(out_html, open_browser=False, notebook=False)
    with open(out_html, "r", encoding="utf-8") as f:
        html = f.read()
    st.components.v1.html(html, height=720, scrolling=True)
    st.download_button("Download graph HTML", data=html, file_name="graph.html", mime="text/html")
    st.caption("Legend: Green=direct edges, Orange=inferred; Red B-nodes=suspicious; Purple ring=anomaly")

with col2:
    st.subheader("Top B-parties")
    topb = top_b_parties(edges, n=12)
    st.dataframe(topb, use_container_width=True)
    st.download_button("Export direct edges (CSV)", data=edges.to_csv(index=False), file_name="edges.csv", mime="text/csv")
    # B-party drill-down
    st.subheader("B-party drill-down")
    b_options = sorted(edges["dst_ip"].unique().tolist())
    sel_b = st.selectbox("Select B-party", options=[""] + b_options)
    if sel_b:
        be = edges[edges["dst_ip"]==sel_b]
        partners = be.groupby("src_ip", as_index=False).agg(
            sessions=("sessions","sum"), total_bytes=("total_bytes","sum")
        ).sort_by("sessions", ascending=False) if hasattr(pd.DataFrame, 'sort_by') else be.groupby("src_ip", as_index=False).agg(
            sessions=("sessions","sum"), total_bytes=("total_bytes","sum")
        ).sort_values(["sessions","total_bytes"], ascending=[False,False])
        st.caption("Partners (A→selected B)")
        st.dataframe(partners, use_container_width=True)
        recent = df_f[df_f["dst_ip"]==sel_b].sort_values("timestamp", ascending=False)[[
            "timestamp","src_ip","dst_port","protocol","bytes_sent","bytes_received","duration_ms","session_id"
        ]].head(100)
        st.caption("Recent sessions to selected B")
        st.dataframe(recent, use_container_width=True)
        # Port/protocol dist
        if len(recent):
            fig2, ax2 = plt.subplots(1,2, figsize=(7,2))
            recent["dst_port"].value_counts().head(8).plot(kind="bar", ax=ax2[0], color="#fde047")
            ax2[0].set_title("Ports")
            recent["protocol"].value_counts().plot(kind="bar", ax=ax2[1], color="#fca5a5")
            ax2[1].set_title("Protocols")
            st.pyplot(fig2, clear_figure=True)
    st.subheader("Inferred A↔B via same relay")
    if len(inferred)==0:
        st.info("No strong overlaps found at current sensitivity.")
    else:
        st.dataframe(inferred, use_container_width=True)
        st.download_button("Export inferred pairs (CSV)", data=inferred.to_csv(index=False), file_name="inferred_pairs.csv", mime="text/csv")
    st.subheader("Anomalous Nodes (ML)")
    st.dataframe(anom.head(15), use_container_width=True)
    st.download_button("Export anomalies (CSV)", data=anom.to_csv(index=False), file_name="anomalies.csv", mime="text/csv")

st.divider()
st.caption("Green edges = direct • Orange edges = inferred (VPN/E2E correlation). Red B nodes = suspicious (stub threat feed). Purple border = anomaly.")
