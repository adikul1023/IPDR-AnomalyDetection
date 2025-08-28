from __future__ import annotations
import pandas as pd
from typing import Set

# Lightweight stub. Replace with AbuseIPDB/OTX/VirusTotal later.
DEFAULT_BAD_IPS = {
    "203.0.113.77", # demo malicious
    "198.51.100.66" # demo malicious
}

def label_suspicious_b(edges: pd.DataFrame, bad_ips: Set[str]|None=None) -> set[str]:
    bad_ips = bad_ips or DEFAULT_BAD_IPS
    b_nodes = set(edges["dst_ip"].unique().tolist())
    sus = set([ip for ip in b_nodes if ip in bad_ips])
    return sus

# --- Future API hooks (placeholders, not used in offline demo) ---
def get_stub_bad_ips() -> Set[str]:
    return set(DEFAULT_BAD_IPS)

def register_bad_ips(ips: Set[str]):
    DEFAULT_BAD_IPS.update(ips)

def abuseipdb_enrich(ip_list: list[str], api_key: str|None=None) -> dict:
    """Placeholder signature for AbuseIPDB enrichment. Returns mapping ip->risk score/info.
    Do not implement network calls in the MVP.
    """
    return {ip: {"source":"stub","score": None} for ip in ip_list}

def otx_enrich(ip_list: list[str], api_key: str|None=None) -> dict:
    """Placeholder signature for AlienVault OTX enrichment. Returns mapping ip->pulse count/info.
    Do not implement network calls in the MVP.
    """
    return {ip: {"source":"stub","pulses": None} for ip in ip_list}
