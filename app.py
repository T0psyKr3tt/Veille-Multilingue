"""
CTS · Contextual Vulnerability Triage & CTI Dashboard
Cyber Threat Intelligence & Contextual Vulnerability Triage (EFREI Master CSC)
"""
import io
import re
import pandas as pd
import plotly.express as px
import requests
import streamlit as st

st.set_page_config(page_title="CTS · Contextual Vulnerability Triage", page_icon="🛡️", layout="wide")

# ───────────────────────── 1. DESIGN & CSS ─────────────────────────
st.markdown("""
<style>
.stApp { background: radial-gradient(1100px 560px at 8% -8%, #1a1f3d 0%, #0a0a0f 58%); color: #f5f5f7; font-family: -apple-system, "SF Pro Display", "Inter", sans-serif; }
header[data-testid="stHeader"], footer, #MainMenu { visibility: hidden; }
.block-container { padding-top: 2rem; max-width: 1300px; }
.hero h1 { font-size: 2.5rem; font-weight: 700; letter-spacing: -.03em; margin: 0; color: #f5f5f7; }
.hero p { color: #98989d; font-size: 1.05rem; margin: 0.3rem 0 1.5rem; }
.kpi { background: rgba(44,44,46,0.55); border: 1px solid rgba(255,255,255,0.08); border-radius: 18px; padding: 18px 22px; backdrop-filter: blur(20px); }
.kpi .l { color: #98989d; font-size: 0.85rem; }
.kpi .v { font-size: 2.4rem; font-weight: 700; letter-spacing: -.03em; line-height: 1.1; margin: 4px 0; }
.kpi .s { color: #6e6e73; font-size: 0.8rem; }
.stTabs [data-baseweb="tab-list"] { gap: 6px; background: rgba(255,255,255,0.06); padding: 4px; border-radius: 14px; }
.stTabs [data-baseweb="tab"] { border-radius: 10px; padding: 8px 18px; color: #98989d; }
.stTabs [aria-selected="true"] { background: rgba(255,255,255,0.14); color: #fff; font-weight: 600; }
.stTabs [data-baseweb="tab-highlight"], .stTabs [data-baseweb="tab-border"] { display: none; }
.stButton>button, .stDownloadButton>button, [data-testid="stFormSubmitButton"]>button { border-radius: 980px; padding: 0.5rem 1.5rem; font-weight: 600; border: 1px solid rgba(255,255,255,0.14); background: #0a84ff; color: #fff; }
div[data-baseweb="input"], div[data-baseweb="select"]>div { border-radius: 12px; }
[data-testid="stDataFrame"] { border-radius: 16px; overflow: hidden; }
</style>
""", unsafe_allow_html=True)

# ───────────────────────── 2. ENTERPRISE ASSETS & CONSTANTS ─────────────────────────
ASSETS = {
    "ASSET-01": {
        "Name": "CTS-Core-Range-Infrastructure (Simulation Engine & Core DB)",
        "Exposure": "Internal Only (Isolated LAN)",
        "Criticality": "Critical",
        "Weight": 1.0,
        "Exp_Weight": -1.5,
    },
    "ASSET-02": {
        "Name": "CTS-Public-Edge-Perimeter (Edge Gateway & External Access)",
        "Exposure": "Internet-Facing (0.0.0.0/0)",
        "Criticality": "Critical",
        "Weight": 1.0,
        "Exp_Weight": 1.5,
    },
    "ASSET-03": {
        "Name": "CTS-Internal-R&D-Environment (Internal LAN & Audit Tools)",
        "Exposure": "Internal Corporate LAN",
        "Criticality": "Moderate",
        "Weight": 0.5,
        "Exp_Weight": -1.0,
    },
    "ASSET-04": {
        "Name": "CTS-Partner-B2B-Services (Monitoring Probes & External APIs)",
        "Exposure": "Semi-Exposed B2B Network",
        "Criticality": "High",
        "Weight": 0.8,
        "Exp_Weight": 0.5,
    },
}

SLAS = {
    "P0": ("Emergency", "< 4h - 24h", "#ff453a"),
    "P1": ("High Priority", "< 72h", "#ff9f0a"),
    "P2": ("Medium Priority", "< 14 Days", "#ffd60a"),
    "P3": ("Low Priority", "< 30-60 Days", "#30d158"),
    "P4": ("Informational / Accepted", "> 60 Days / Accepted", "#64d2ff")
}

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

DEFAULT_CORPUS = [
    {"cve": "CVE-2026-88771", "asset": "ASSET-02", "cvss": 9.5, "epss": 0.95, "kev": True, "active": True, "desc": "Citrix NetScaler Unauth RCE (Zero-day EFREI Case)"},
    {"cve": "CVE-2026-88772", "asset": "ASSET-02", "cvss": 9.5, "epss": 0.92, "kev": True, "active": True, "desc": "Citrix NetScaler DTLS Memory Overflow (Zero-day EFREI Case)"},
    {"cve": "CVE-2024-3094",  "asset": "ASSET-03", "cvss": 10.0,"epss": 0.0005,"kev": False,"active": True, "desc": "XZ Utils Supply-Chain Backdoor (Not weaponized in prod)"},
    {"cve": "CVE-2023-34362", "asset": "ASSET-04", "cvss": 9.8, "epss": 0.97, "kev": True, "active": True, "desc": "MOVEit Transfer SQLi RCE (Massive ransomware exploitation)"},
    {"cve": "CVE-2023-4863",  "asset": "ASSET-01", "cvss": 8.8, "epss": 0.0002,"kev": False,"active": True, "desc": "libwebp Heap Buffer Overflow (Complex client preconditions)"},
    {"cve": "CVE-2024-21887", "asset": "ASSET-02", "cvss": 9.1, "epss": 0.93, "kev": True, "active": True, "desc": "Ivanti Connect Secure Command Injection (chained with CVE-2023-46805 auth bypass)"},
    {"cve": "CVE-2021-44228", "asset": "ASSET-01", "cvss": 10.0,"epss": 0.97, "kev": True, "active": True, "desc": "Apache Log4j2 RCE (Log4Shell - Isolated Core LAN)"},
    {"cve": "CVE-2023-23397", "asset": "ASSET-03", "cvss": 9.8, "epss": 0.95, "kev": True, "active": True, "desc": "MS Outlook NTLM Privilege Escalation (Internal mail trigger)"},
    {"cve": "CVE-2023-22515", "asset": "ASSET-03", "cvss": 8.5, "epss": 0.85, "kev": True, "active": True, "desc": "Atlassian Confluence Data Center Auth Bypass"},
    {"cve": "CVE-2021-4034",  "asset": "ASSET-01", "cvss": 7.8, "epss": 0.0008,"kev": False,"active": True, "desc": "Polkit Pkexec Local Privilege Escalation (Linux)"},
    {"cve": "CVE-2020-1472",  "asset": "ASSET-01", "cvss": 10.0,"epss": 0.97, "kev": True, "active": True, "desc": "Netlogon Zerologon (Internal Domain Controller)"},
    {"cve": "CVE-2022-30190", "asset": "ASSET-03", "cvss": 7.8, "epss": 0.95, "kev": True, "active": False,"desc": "MSDT Follina (Service Disabled / Mitigated)"},
    {"cve": "CVE-2024-1086",  "asset": "ASSET-03", "cvss": 7.8, "epss": 0.0005,"kev": False,"active": True, "desc": "Linux Kernel Use-After-Free LPE"},
    {"cve": "CVE-2023-38606", "asset": "ASSET-03", "cvss": 5.5, "epss": 0.0001,"kev": False,"active": True, "desc": "Apple macOS Kernel LPE (Complex post-exploitation)"},
    {"cve": "CVE-2021-34527", "asset": "ASSET-01", "cvss": 8.8, "epss": 0.0015,"kev": False,"active": False,"desc": "PrintNightmare (Print Spooler Service Disabled)"}
]

# ───────────────────────── 3. LIVE THREAT INTEL APIS ─────────────────────────
@st.cache_data(ttl=3600, show_spinner=False)
def fetch_kev():
    """Return the set of CVE IDs in the CISA KEV catalog, or None if the feed is unreachable."""
    try:
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
        return {v["cveID"] for v in r.json()["vulnerabilities"]} if r.status_code == 200 else None
    except Exception:
        return None

@st.cache_data(ttl=3600, show_spinner=False)
def fetch_epss(cve: str):
    """Return the EPSS probability (0-1), or None if the API is unreachable / CVE unknown."""
    try:
        r = requests.get(f"https://api.first.org/data/v1/epss?cve={cve}", timeout=10)
        data = r.json()
        if data.get("status") == "OK" and data.get("data"):
            return float(data["data"][0]["epss"])
    except Exception:
        pass
    return None

@st.cache_data(ttl=3600, show_spinner=False)
def fetch_cvss_desc(cve: str):
    """NVD API 2.0 -> (cvss, description). cvss is None if unavailable (no silent default)."""
    try:
        r = requests.get("https://services.nvd.nist.gov/rest/json/cve/2.0", params={"cveId": cve}, timeout=15)
        if r.status_code == 200 and r.json().get("vulnerabilities"):
            c = r.json()["vulnerabilities"][0]["cve"]
            desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
            for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
                if c.get("metrics", {}).get(key):
                    return float(c["metrics"][key][0]["cvssData"]["baseScore"]), desc[:150]
            return None, desc[:150]
    except Exception:
        pass
    return None, "Description unavailable"

def enrich_cve(cve, asset, active, kev_set):
    """Query live feeds for one CVE. Returns (item, warnings). Missing data is flagged, never silently invented."""
    warns = []
    epss = fetch_epss(cve)
    cvss, desc = fetch_cvss_desc(cve)
    if epss is None:
        warns.append(f"{cve}: EPSS unavailable, 0.1% assumed")
        epss = 0.001
    if cvss is None:
        warns.append(f"{cve}: CVSS unavailable, 7.5 assumed")
        cvss = 7.5
    return {"cve": cve, "asset": asset, "cvss": cvss, "epss": epss, "kev": cve in kev_set, "active": active, "desc": desc}, warns

def load_kev_or_warn():
    kev_set = fetch_kev()
    if kev_set is None:
        st.warning("CISA KEV feed unreachable: KEV status defaults to False for all CVEs below.")
        return set()
    return kev_set

# ───────────────────────── 4. CONTEXTUAL SCORING ALGORITHM ─────────────────────────
def calculate_score(cvss, epss, kev, asset_id, active):
    """Score = 0.35*CVSS + 0.35*EPSS*10 + KEV(+2) + Exposure + AssetWeight + Inactive(-4), capped to [0,10].
    Returns (capped score, priority, raw uncapped score). Raw is used only to break ties between capped 10.0 scores."""
    asset_info = ASSETS[asset_id]
    cvss_w = 0.35 * cvss
    epss_w = 0.35 * (epss * 10)
    kev_b = 2.0 if kev else 0.0
    exp_b = asset_info["Exp_Weight"]
    asset_b = asset_info["Weight"]
    penalty = 0.0 if active else -4.0
    
    raw = cvss_w + epss_w + kev_b + exp_b + asset_b + penalty
    score = min(10.0, max(0.0, round(raw, 2)))
    
    if score >= 8.5: priority = "P0"
    elif score >= 6.8: priority = "P1"
    elif score >= 4.8: priority = "P2"
    elif score >= 2.8: priority = "P3"
    else: priority = "P4"
    
    return score, priority, raw

# ───────────────────────── 5. USER INTERFACE ─────────────────────────
def render_results_dashboard(items):
    results = []
    for item in items:
        score, prio, raw = calculate_score(item["cvss"], item["epss"], item["kev"], item["asset"], item["active"])
        sla_name, sla_time, color = SLAS[prio]
        results.append({
            "Priority": prio, "Score": score, "Raw": round(raw, 2), "CVE_ID": item["cve"],
            "Asset_ID": item["asset"], "Asset_Name": ASSETS[item["asset"]]["Name"],
            "CVSS": item["cvss"], "EPSS": item["epss"], "KEV": item["kev"],
            "Active": item["active"], "Exposure": ASSETS[item["asset"]]["Exposure"],
            "SLA": sla_time, "Color": color, "Description": item["desc"]
        })
    df = pd.DataFrame(results).sort_values("Raw", ascending=False).reset_index(drop=True)

    st.write("")
    st.markdown("### 2. Algorithmic Risk Triage Output")
    
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.markdown(f'<div class="kpi"><div class="l">P0 · Emergency</div><div class="v" style="color:#ff453a">{(df["Priority"]=="P0").sum()}</div><div class="s">&lt; 4h-24h SLA</div></div>', unsafe_allow_html=True)
    k2.markdown(f'<div class="kpi"><div class="l">P1 · High</div><div class="v" style="color:#ff9f0a">{(df["Priority"]=="P1").sum()}</div><div class="s">&lt; 72h SLA</div></div>', unsafe_allow_html=True)
    k3.markdown(f'<div class="kpi"><div class="l">P2 · Medium</div><div class="v" style="color:#ffd60a">{(df["Priority"]=="P2").sum()}</div><div class="s">&lt; 14 Days SLA</div></div>', unsafe_allow_html=True)
    k4.markdown(f'<div class="kpi"><div class="l">P3 · Low</div><div class="v" style="color:#30d158">{(df["Priority"]=="P3").sum()}</div><div class="s">&lt; 30-60d SLA</div></div>', unsafe_allow_html=True)
    k5.markdown(f'<div class="kpi"><div class="l">P4 · Tolerated</div><div class="v" style="color:#64d2ff">{(df["Priority"]=="P4").sum()}</div><div class="s">&gt; 60d / Accepted</div></div>', unsafe_allow_html=True)

    st.write("")
    g1, g2 = st.columns([1, 1.4])
    layout = dict(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", margin=dict(t=30, b=20, l=10, r=10))
    colors_map = {k: v[2] for k, v in SLAS.items()}
    
    fig1 = px.pie(df, names="Priority", hole=0.6, color="Priority", color_discrete_map=colors_map, title="Risk Tier Distribution")
    fig1.update_layout(**layout)
    g1.plotly_chart(fig1, use_container_width=True)

    fig2 = px.scatter(df, x="CVSS", y="EPSS", color="Priority", size="Score", hover_name="CVE_ID",
                      hover_data=["Asset_Name", "Exposure"], color_discrete_map=colors_map,
                      title="CVSS (Severity) vs EPSS (Exploit Probability)")
    fig2.update_layout(**layout, xaxis=dict(range=[0, 10.5]), yaxis=dict(range=[0, 1.05]))
    g2.plotly_chart(fig2, use_container_width=True)

    st.markdown("### 3. Detailed Prioritized Remediation Agenda")
    df.insert(0, "Rank", range(1, len(df) + 1))
    styled_df = df[["Rank", "Priority", "Score", "CVE_ID", "Asset_ID", "Asset_Name", "CVSS", "EPSS", "KEV", "Active", "SLA", "Description"]]
    st.dataframe(styled_df, use_container_width=True, hide_index=True)

    st.download_button("Export CSV Report", df.to_csv(index=False, sep=";").encode("utf-8-sig"), "cts_triage_report.csv", "text/csv")

def main():
    st.markdown('<div class="hero"><h1>Contextual Vulnerability Triage & CTI Dashboard</h1>'
                '<p>Cyber Test Systems · End-to-End Operational Pipeline (EFREI Master CSC)</p></div>', unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["1. Matrix Triage & Live Script", "2. Deep-Dive CTI Dossier (P0)", "3. Executive Board Arbitration"])

    with tab1:
        st.markdown("### Data Input Mode & Script Execution")
        input_mode = st.radio("Select data source to prove the live script execution:", 
                              ["1. Default EFREI Corpus (15 CVEs)", "2. Manual Input (1 to 5 CVEs)", "3. Import Excel / CSV File"], horizontal=True)

        selected_corpus = []

        if input_mode == "1. Default EFREI Corpus (15 CVEs)":
            selected_corpus = DEFAULT_CORPUS

        elif input_mode == "2. Manual Input (1 to 5 CVEs)":
            st.info("Enter CVE IDs below. The script will query live Threat Intel APIs (EPSS & KEV) to compute contextual priorities.")
            with st.form("manual_form"):
                cols = st.columns([2, 2, 2])
                cols[0].caption("CVE ID")
                cols[1].caption("Target CTS Asset")
                cols[2].caption("Active Component?")
                
                user_inputs = []
                for i in range(5):
                    c = st.columns([2, 2, 2])
                    cve = c[0].text_input("cve", key=f"cve_{i}", placeholder="CVE-2023-34362", label_visibility="collapsed")
                    asset = c[1].selectbox("asset", list(ASSETS.keys()), key=f"ast_{i}", label_visibility="collapsed")
                    active = c[2].checkbox("Active in Prod", value=True, key=f"act_{i}", label_visibility="collapsed")
                    user_inputs.append((cve, asset, active))
                
                submit = st.form_submit_button("Run Live Dynamic Analysis")
                
                if submit:
                    kev_set = load_kev_or_warn()
                    for cve_id, asset_id, act in user_inputs:
                        cve_clean = cve_id.strip().upper()
                        if cve_clean and not CVE_RE.match(cve_clean):
                            st.warning(f"Ignored invalid CVE ID: {cve_id}")
                        elif cve_clean:
                            item, warns = enrich_cve(cve_clean, asset_id, act, kev_set)
                            selected_corpus.append(item)
                            for w in warns:
                                st.warning(w)

        elif input_mode == "3. Import Excel / CSV File":
            uploaded_file = st.file_uploader("Select an Excel (.xlsx) or CSV (.csv) file with a 'CVE_ID' column", type=["csv", "xlsx"])
            col_a, col_b = st.columns(2)
            default_asset = col_a.selectbox("Default CTS Asset for uploaded batch:", list(ASSETS.keys()))
            default_active = col_b.checkbox("Active components in prod?", value=True)
            
            if uploaded_file is not None:
                if st.button("Process File (Query Live APIs)"):
                    try:
                        df_raw = pd.read_csv(uploaded_file, sep=None, engine="python") if uploaded_file.name.endswith(".csv") else pd.read_excel(uploaded_file)
                        if "CVE_ID" in df_raw.columns:
                            kev_set = load_kev_or_warn()
                            cve_list = list(dict.fromkeys(str(v).strip().upper() for v in df_raw["CVE_ID"].dropna()))
                            bar = st.progress(0, text="Fetching Live Threat Intel APIs...")
                            
                            for idx, cve_id in enumerate(cve_list):
                                if CVE_RE.match(cve_id):
                                    item, warns = enrich_cve(cve_id, default_asset, default_active, kev_set)
                                    selected_corpus.append(item)
                                    for w in warns:
                                        st.warning(w)
                                else:
                                    st.warning(f"Ignored invalid CVE ID: {cve_id}")
                                bar.progress((idx + 1) / len(cve_list))
                            bar.empty()
                        else:
                            st.error("The file must contain a 'CVE_ID' header column.")
                    except Exception as e:
                        st.error(f"Error reading file: {e}")

        st.markdown("### 1. Enterprise Perimeter & Asset Mapping")
        cols = st.columns(4)
        for i, (aid, ainfo) in enumerate(ASSETS.items()):
            cols[i].markdown(f'<div class="kpi"><div class="l">{aid}</div><div class="v" style="font-size:1.2rem;color:#f5f5f7">{ainfo["Name"]}</div><div class="s">{ainfo["Exposure"]}<br><b>Criticality: {ainfo["Criticality"]}</b></div></div>', unsafe_allow_html=True)

        with st.expander("Scoring formula & tier thresholds"):
            st.code("Score = 0.35*CVSS + 0.35*(EPSS*10) + KEV(+2.0) + Exposure + AssetWeight + Inactive(-4.0)   [capped 0-10]\n"
                    "Exposure: Internet +1.5 | B2B +0.5 | Internal LAN -1.0 | Isolated LAN -1.5\n"
                    "Asset weight: Critical 1.0 | High 0.8 | Moderate 0.5\n"
                    "Tiers: P0 >= 8.5 | P1 >= 6.8 | P2 >= 4.8 | P3 >= 2.8 | P4 < 2.8", language="text")

        if selected_corpus:
            render_results_dashboard(selected_corpus)
        else:
            st.info("Select or import CVEs to display analysis results.")

    # ───────────────────────── TAB 2 & 3 (CTI DOSSIER & ARBITRATION) ─────────────────────────
    with tab2:
        st.markdown("## Deep-Dive Threat Intelligence Dossier")
        st.info("Focus P0 Incident: **CVE-2026-88771** & **CVE-2026-88772** (Citrix NetScaler Zero-Day Attacks)")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("### 1. Diamond Model of Intrusion")
            st.markdown("""
            * **Adversary**: UNC5195 / State-sponsored & Ransomware affiliates (Financially motivated / Espionage).
            * **Capabilities**: Unauthenticated Memory Leak & RCE exploit chain, DTLS payload crafting, memory injection.
            * **Infrastructure**: Compromised Residential Proxies, Bulletproof C2 servers (185.220.x.x), Tor exit nodes.
            * **Victim**: Perimeter Assets (`ASSET-02` / CTS-CSG Gateway), Public Edge NetScaler 14.1/13.1 instances.
            """)
            st.markdown("### 2. MITRE ATT&CK Mapping")
            st.markdown("""
            * **T1190 - Exploit Public-Facing Application**: Direct RCE on public NetScaler gateway (`ASSET-02`).
            * **T1068 - Exploitation for Privilege Escalation**: Bypassing memory protections to gain root permissions.
            * **T1021.001 - Remote Services (RDP/SSH)**: Pivoting from perimeter gateway to internal core assets (`ASSET-01`).
            * **T1070.004 - Indicator Removal on Host**: Clearing system logs and memory artifacts post-exploitation.
            """)
        with c2:
            st.markdown("### 3. Source Confrontation (NATO Admiralty Code)")
            st.markdown("""
            | Source Type | Agency / Source | Key Claim / Statement | Reliability (A-F) | Credibility (1-6) | Analytical Bias / Evaluation |
            | :--- | :--- | :--- | :---: | :---: | :--- |
            | **Vendor Bulletin** | Citrix (CTX697096) | "Limited zero-day exploits observed; patch available." | **B** | **3** | Commercial Bias: Minimized impact to protect brand reputation; technically accurate on the patch but contradicted by CISA/CERT-FR telemetry on scale. |
            | **Sovereign Agency** | CISA KEV / CERT-FR | "Active exploitation worldwide prior to patches. Emergency isolation required." | **A** | **1** | Direct Telemetry: Unbiased operational incident data from national CSIRTs. |
            | **Private Research** | watchTowr Cyber | "Unpatched RCE zero-day actively weaponized in wild." | **B** | **1** | Research Bias: High technical credibility, verified 24h prior to official vendor acknowledgment. |
            """)

    with tab3:
        st.markdown("## Executive Board Arbitration & CISO Pitch")
        st.warning("Scenario: The CEO demands an immediate shutdown of `ASSET-01` (Core Engine) due to media hype around a CVSS 10.0 flaw (Log4Shell / XZ Utils).")
        st.markdown("""
        ### Executive Pitch Script (3-Minute Board Speech)
        > **"Mr. Chief Executive, Members of the Board,**
        > 
        > I understand your grave concern regarding recent news headlines highlighting a **CVSS 10.0** vulnerability. However, as your Chief Information Security Officer, I must strongly advise **AGAINST** shutting down **ASSET-01** (Our Core Engine).
        >
        > **1. Why shutting down ASSET-01 is counterproductive:**
        > - **Zero Exposure**: ASSET-01 is strictly isolated inside our internal network with no direct route from the Internet.
        > - **Financial & Operational Paralysis**: An unplanned shutdown of ASSET-01 will cause **100% downtime** for our core revenue systems and trigger heavy NIS2/DORA regulatory non-compliance fines.
        > - **No Attack Path**: Log4Shell and Zerologon are known to be exploited elsewhere, but both need network access to ASSET-01, which an attacker does not have today. Our score ranks them P1 (< 72h), not P0.
        >
        > **2. Where the TRUE Emergency is (Priority P0):**
        > - Our Threat Intelligence pipeline has flagged **CVE-2026-88771** on **ASSET-02** (Cyber Jump Gateway) as a true **P0 Emergency**.
        > - It sits directly on our Internet perimeter (0.0.0.0/0), has a high **EPSS score (95%)**, and is actively listed in the **CISA KEV catalog** as being weaponized right now.
        >
        > **3. Recommended Decision & Compromise:**
        > 1. **Immediate P0 Deployment**: Redirect all emergency patching capacity to virtual-patch and update **ASSET-02 within 4 hours**.
        > 2. **Compensating Controls for ASSET-01**: Enforce strict internal micro-segmentation and enhanced EDR monitoring around ASSET-01 **without any service interruption**.
        >
        > 3. **Tiered plan**: < 4h containment of ASSET-02 (ACLs, disable DTLS, WAF virtual patch); < 48h firmware upgrade and IOC sweep; < 30 days ZTNA redesign and automated KEV sync. ASSET-01 is patched inside its next planned maintenance window (< 72h target).
        >
        > I ask the Board to approve this threat-informed action plan to protect both our perimeter and our business continuity."
        """)

if __name__ == "__main__":
    main()
