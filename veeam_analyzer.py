#!/usr/bin/env python3
"""
veeam_analyzer.py  —  Veeam Site Analyzer  (single-file, no external dependencies beyond pip packages)
======================================================================================================
Parses Veeam Health Check (VHC) HTML reports and RVTools Excel exports, cross-references
findings against live Veeam v13 documentation, and generates:
  • Per-site HTML report with VM inventory, datastore capacity, storage vendor detection,
    best-practice gaps (cited to Veeam docs), and VHC compliance findings
  • SVG architecture diagram (requires a VHC HTML file)
  • JSON analysis output
  • Fleet-wide master summary (batch mode)

USAGE
-----
Single site:
    python3 veeam_analyzer.py site.html [--rvtools rvtools.xlsx] [--output report.json] [--no-fetch]

Batch mode (auto-discovers all .xlsx and .html in scan folder):
    python3 veeam_analyzer.py --batch [--scan-dir PATH] [--output-dir PATH] [--no-fetch]

REQUIREMENTS
    pip install beautifulsoup4 requests openpyxl

DOC SOURCES FETCHED AT RUNTIME
    https://helpcenter.veeam.com/docs/vbr/userguide/overview.html?ver=13
    https://helpcenter.veeam.com/rn/veeam_backup_13_0_2_release_notes.html
    https://bp.veeam.com/vbr
    https://www.veeam.com/knowledge-base.html
    https://helpcenter.veeam.com/docs/vbr/userguide/planning.html?ver=13
"""
from __future__ import annotations
import argparse, json, logging, math, re, sys
from datetime import datetime
from pathlib import Path

log = logging.getLogger("veeam_analyzer")
logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

try:
    import openpyxl
    OPENPYXL_OK = True
except ImportError:
    OPENPYXL_OK = False

try:
    import requests
    from bs4 import BeautifulSoup
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

_SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_SCAN_DIR   = _SCRIPT_DIR / "Magnera - remote site review"
DEFAULT_OUTPUT_DIR = _SCRIPT_DIR / "output architecture"

# ── Veeam doc URLs ────────────────────────────────────────────────────────────
VEEAM_DOC_URLS = {
    "user_guide":      "https://helpcenter.veeam.com/docs/vbr/userguide/overview.html?ver=13",
    "release_notes":   "https://helpcenter.veeam.com/rn/veeam_backup_13_0_2_release_notes.html",
    "best_practices":  "https://bp.veeam.com/vbr",
    "knowledge_base":  "https://www.veeam.com/knowledge-base.html",
    "upgrade_planning":"https://helpcenter.veeam.com/docs/vbr/userguide/planning.html?ver=13",
}
FETCH_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; VeeamAnalyzer/3.0)"}

# ── v13 upgrade blockers ──────────────────────────────────────────────────────
VEEAM_V13_HARD_BLOCKERS = [
    {"id":"sql_version","check":"Config DB SQL Server version","requirement":"SQL Server 2016 or later required",
     "detail":"v13 requires SQL 2016+ for the configuration database.","source":"release_notes"},
    {"id":"legacy_metadata","check":"Legacy backup metadata format","requirement":"No pre-v11 legacy metadata present",
     "detail":"Backup chains created before VBR v11 must be converted before upgrading.","source":"release_notes"},
    {"id":"legacy_backup_copy","check":"Legacy backup copy jobs (pre-v9)","requirement":"No pre-v9 backup copy job format",
     "detail":"Backup copy jobs created before v9 must be recreated before upgrading to v13.","source":"release_notes"},
    {"id":"cloud_connect_portal","check":"Cloud Connect Portal in use","requirement":"Cloud Connect Portal not in use (removed in v13)",
     "detail":"The Cloud Connect Portal is removed in v13.","source":"release_notes"},
    {"id":"veeam_agent_localdb","check":"Pre-v6 Veeam Agents using LocalDB","requirement":"No Veeam Agents below v6 using LocalDB",
     "detail":"Agents using LocalDB from versions prior to v6 are incompatible with v13.","source":"release_notes"},
]

VEEAM_V13_DEPRECATED_FEATURES = [
    {"id":"reversed_incremental","check":"Reversed incremental backup mode","requirement":"Must not be in use",
     "detail":"Reversed incremental chain type is removed in v13. Switch to forward incremental."},
    {"id":"restore_point_retention","check":"Restore-point based retention","requirement":"Must not be in use",
     "detail":"Retention by restore points is deprecated. Use days-based retention."},
    {"id":"sequential_tape","check":"Sequential tape libraries","requirement":"Must not be in use",
     "detail":"Sequential tape library support is removed in v13."},
    {"id":"non_per_machine_chains","check":"Non-per-machine backup chains","requirement":"All chains must be per-machine format",
     "detail":"Legacy non-per-machine chains are removed. Per-VM backup files must be enabled."},
    {"id":"runtime_data_mover","check":"Run-time data mover","requirement":"Must not be configured",
     "detail":"The run-time data mover option is removed."},
    {"id":"u_air","check":"U-AIR (Universal Application-Item Recovery)","requirement":"Must not be in use",
     "detail":"U-AIR is removed. Use Veeam Explorers for application-item recovery."},
]

VEEAM_V13_SECURITY_RELEVANCE = {
    "Local Security Authority Server Service (LSASS) running as protected process":
        "HIGH — LSASS protection prevents credential theft. v13 has CVSS 9.9 RCE CVEs; ensure OS hardening before exposing REST API.",
    "Hardened repositories are not hosted in virtual machines":
        "HIGH — A hardened repo in a VM provides no real immutability guarantee.",
    "Hardened repositories have SSH disabled":
        "HIGH — SSH on a hardened repo is a direct attack surface.",
    "Host to proxy traffic encryption should be enabled for the Network transport mode":
        "MEDIUM — v13 enforces stricter transport security defaults.",
    "Remote registry service is disabled":
        "MEDIUM — Remote registry is a lateral movement vector.",
    "NetBIOS protocol should be disabled on all network interfaces":
        "MEDIUM — NetBIOS is leveraged in NTLM relay attacks.",
    "Windows Script Host is disabled":
        "MEDIUM — WSH is commonly abused in malware delivery chains.",
    "Windows firewall is enabled":
        "MEDIUM — v13 requires port 443 for web UI/REST API.",
    "Credentials and encryption passwords rotates annually":
        "MEDIUM — v13 introduces improved credential vault logging.",
    "Unknown Linux servers are not trusted automatically":
        "MEDIUM — Auto-trust of SSH fingerprints is a supply chain risk.",
    "Remote powershell is disabled (WinRM service)":
        "LOW — WinRM is used by attackers for lateral movement.",
    "Backup services run under the LocalSystem account":
        "LOW — LocalSystem is overly privileged. v13 supports least-privilege service accounts.",
}

WORKLOAD_INCOMPATIBILITIES = [
    {"component":"SQL Server 2025","veeam_version":"v12.x","issue":"Transaction log backup failure",
     "detail":"Veeam v12 cannot process SQL Server 2025 transaction logs. Requires upgrade to v13.","severity":"CRITICAL"},
    {"component":"Windows Server 2016","veeam_version":"v12/v13","issue":"OS End of Life (October 14, 2025)",
     "detail":"WS2016 reached EOL Oct 14 2025. No security patches issued.","severity":"HIGH"},
    {"component":"ReFS volumes (in-place OS upgrade)","veeam_version":"v12/v13","issue":"Data loss risk on in-place upgrade (KB2792)",
     "detail":"In-place upgrade on a server with ReFS Veeam extents can corrupt the volume. Evacuate extents first.","severity":"CRITICAL"},
    {"component":"Veeam ONE / Enterprise Manager","veeam_version":"v13 upgrade","issue":"Must be upgraded before VBR",
     "detail":"v13 upgrade order: Veeam ONE → Enterprise Manager → VBR.","severity":"HIGH"},
]

DS_WARN_PCT = 75
DS_CRIT_PCT = 85

STORAGE_VENDORS = [
    ("Pure Storage",  ["pure","purestorage","fa-","flasharray"]),
    ("NetApp ONTAP",  ["netapp","ontap","aggr","na_","svm_"]),
    ("Dell EMC",      ["emc","vplex","unity","vnx","powerstore","isilon","sc_"]),
    ("HPE",           ["3par","primera","nimble","alletra","msa","lefthand"]),
    ("Nutanix",       ["nutanix","ntnx"]),
    ("IBM",           ["ibm","storwize","flashsystem","ds8"]),
    ("Hitachi",       ["hitachi","hus","g200","g400","vsp"]),
    ("vSAN",          ["vsan","vsandatastore"]),
]

EOL_GUEST_PATTERNS = [
    "Windows Server 2008","Windows Server 2012","Windows Server 2003",
    "Windows XP","Windows Vista","Windows 7",
    "CentOS 6","CentOS 7","CentOS 8",
    "RHEL 6","Red Hat Enterprise Linux 6",
    "Ubuntu 14","Ubuntu 16","Ubuntu 18",
    "Debian 8","Debian 9","SLES 11","SLES 12",
]

ESXI_STATUS = {"8":("current","#27ae60"),"7":("supported","#e67e22"),"6":("EOL","#c0392b"),"5":("EOL","#c0392b")}
STATUS_PASS="PASS"; STATUS_FAIL="FAIL"; STATUS_WARN="WARN"; STATUS_UNKNOWN="UNKNOWN"
_ENV_SMALL=50; _ENV_MEDIUM=200; _VMS_PER_PROXY=30


# ═════════════════════════════════════════════════════════════════════════════
# SHARED HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _esc(s):
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def _mib_to_gib(val):
    try: return round(float(str(val).replace(",","")) / 1024, 1)
    except: return 0.0

def detect_storage_vendor(name, ds_type):
    n = name.lower(); t = ds_type.lower()
    for vendor, patterns in STORAGE_VENDORS:
        if any(p in n for p in patterns): return vendor
    if t in ("nfs","nfs41"): return "NFS/NAS"
    if t == "vsan": return "vSAN"
    if t == "vmfs": return "VMFS (vendor unknown)"
    return "Unknown"


# ═════════════════════════════════════════════════════════════════════════════
# RVTOOLS PARSER  (enhanced — vInfo, vDatastore, vHost, vSnapshot)
# ═════════════════════════════════════════════════════════════════════════════

def _sheet_rows(wb, sheet_name):
    if sheet_name not in wb.sheetnames: return []
    ws = wb[sheet_name]
    rows = list(ws.iter_rows(values_only=True))
    if not rows: return []
    headers = [str(h).strip() if h is not None else "" for h in rows[0]]
    out = []
    for row in rows[1:]:
        if all(c is None for c in row): continue
        out.append({h:(v if v is not None else "") for h,v in zip(headers,row)})
    return out

def parse_rvtools(xlsx_path):
    if not OPENPYXL_OK:
        log.error("openpyxl missing — pip install openpyxl"); return {"error":"openpyxl_missing"}
    log.info(f"  Parsing RVTools: {Path(xlsx_path).name}")
    try: wb = openpyxl.load_workbook(xlsx_path, read_only=True, data_only=True)
    except Exception as e: log.error(f"  Cannot open: {e}"); return {"error":str(e)}

    # vInfo
    vms = []
    for r in _sheet_rows(wb,"vInfo"):
        name = str(r.get("VM","")).strip()
        if not name or name.lower()=="none": continue
        is_tmpl = str(r.get("Template","")).strip().lower() in ("true","yes","1")
        os_t = str(r.get("OS according to the VMware Tools","")).strip()
        os_c = str(r.get("OS according to the configuration file","")).strip()
        os_str = os_t if os_t and os_t.lower() not in ("","none","unknown") else os_c
        try: mem_mib = float(str(r.get("Memory",0) or 0))
        except: mem_mib=0.0
        try: cpu = int(r.get("CPUs", r.get("Num CPU",0)) or 0)
        except: cpu=0
        try: prov = float(str(r.get("Provisioned MiB", r.get("Provisioned MB",0)) or 0))
        except: prov=0.0
        tools_st = str(r.get("VMware Tools Status", r.get("Tools Status",""))).strip()
        consolidate = str(r.get("Consolidation Needed","")).strip().lower() in ("true","yes","1")
        try: snap_c = int(str(r.get("Snapshots","0")).strip() or 0)
        except: snap_c=0
        vms.append({"name":name,"powerstate":str(r.get("Powerstate","")).strip(),
            "template":is_tmpl,"os":os_str,"cluster":str(r.get("Cluster","")).strip(),
            "host":str(r.get("Host","")).strip(),"datacenter":str(r.get("Datacenter","")).strip(),
            "cpu":cpu,"memory_gib":round(mem_mib/1024,1),"provisioned_gib":round(prov/1024,1),
            "tools_status":tools_st,"snapshots":snap_c,"consolidation_needed":consolidate})

    # vDatastore
    datastores=[]; seen=set()
    for r in _sheet_rows(wb,"vDatastore"):
        name=str(r.get("Name","")).strip()
        if not name or name in seen: continue
        seen.add(name)
        ds_type=str(r.get("Type","")).strip()
        cap_gib=_mib_to_gib(r.get("Capacity MiB", r.get("Capacity MB",0)))
        free_gib=_mib_to_gib(r.get("Free MiB", r.get("Free Space MB",0)))
        fp=str(r.get("Free %", r.get("Free Space %",""))).replace("%","").strip()
        try: free_pct=float(fp)
        except: free_pct=round(free_gib/cap_gib*100,1) if cap_gib else 0.0
        datastores.append({"name":name,"type":ds_type,"vendor":detect_storage_vendor(name,ds_type),
            "cap_gib":cap_gib,"free_gib":free_gib,"used_pct":round(100-free_pct,1),
            "num_vms":str(r.get("# VMs", r.get("VMs",""))).strip(),
            "cluster":str(r.get("Cluster name", r.get("Cluster",""))).strip()})

    # vHost
    hosts=[]
    for r in _sheet_rows(wb,"vHost"):
        hname=str(r.get("Host","")).strip()
        if not hname: continue
        esxi_v=str(r.get("ESX Version", r.get("ESXi Version",""))).strip()
        m=re.search(r"(\d+\.\d+)",esxi_v); ver_s=m.group(1) if m else esxi_v
        try: cores=int(r.get("# Cores", r.get("# CPU Cores",0)) or 0)
        except: cores=0
        try: mem_g=round(float(str(r.get("Memory", r.get("# Memory",0)) or 0))/1024,1)
        except: mem_g=0.0
        hosts.append({"name":hname,"cluster":str(r.get("Cluster","")).strip(),
            "datacenter":str(r.get("Datacenter","")).strip(),
            "cpu_model":str(r.get("CPU Model","")).strip(),
            "cores":cores,"memory_gib":mem_g,"esxi_ver":ver_s,"full_ver":esxi_v})

    # vSnapshot
    snapshots=[]
    for r in _sheet_rows(wb,"vSnapshot"):
        vm=str(r.get("VM","")).strip()
        if not vm: continue
        snapshots.append({"vm":vm,"name":str(r.get("Name","")).strip(),
            "created":str(r.get("Created","")).strip(),
            "size_gib":_mib_to_gib(r.get("Size MiB", r.get("Size MB",0)))})

    wb.close()
    non_tmpl=[v for v in vms if not v["template"]]
    powered=[v for v in non_tmpl if v["powerstate"]=="poweredOn"]
    powered_off=[v for v in non_tmpl if v["powerstate"]=="poweredOff"]
    tmpls=[v for v in vms if v["template"]]
    log.info(f"    vms={len(non_tmpl)} ({len(powered)} on, {len(powered_off)} off), "
             f"templates={len(tmpls)}, datastores={len(datastores)}, hosts={len(hosts)}, snapshots={len(snapshots)}")
    return {"source":Path(xlsx_path).name,"error":None,"vms":vms,
            "non_templates":non_tmpl,"powered_on":powered,"powered_off":powered_off,
            "templates":tmpls,"datastores":datastores,"hosts":hosts,"snapshots":snapshots,
            # compat aliases for legacy functions
            "vinfo":non_tmpl,"vdatastore":datastores,"vhost":hosts}


# ═════════════════════════════════════════════════════════════════════════════
# VHC HTML PARSER
# ═════════════════════════════════════════════════════════════════════════════

def _parse_table(section_div, max_rows=None):
    if not section_div: return []
    rows=section_div.find_all("tr")
    if not rows: return []
    headers=[th.get_text(strip=True) for th in rows[0].find_all(["th","td"])]
    records=[]
    for row in rows[1:]:
        cells=[td.get_text(strip=True) for td in row.find_all(["td","th"])]
        if not cells: continue
        records.append(dict(zip(headers,cells)))
        if max_rows and len(records)>=max_rows: break
    return records

def _icon_to_bool(val):
    if "✅" in val: return True
    if "☐" in val: return False
    return None

def _parse_multi_header_table(section_div):
    if not section_div: return {}
    rows=section_div.find_all("tr"); result={}; i=0
    while i<len(rows)-1:
        headers=[td.get_text(strip=True) for td in rows[i].find_all(["th","td"])]
        values=[td.get_text(strip=True) for td in rows[i+1].find_all(["td","th"])]
        if headers and values and len(headers)==len(values):
            for h,v in zip(headers,values):
                if h: result[h]=v
            i+=2
        else: i+=1
    return result

def parse_vhc(html_path):
    log.info(f"Parsing VHC: {html_path}")
    if not REQUESTS_OK:
        log.error("beautifulsoup4 missing — pip install beautifulsoup4"); return {}
    with open(html_path,encoding="utf-8") as f:
        soup=BeautifulSoup(f.read(),"html.parser")
    data={}
    vbr_div=soup.find("div",id="vbrserver")
    vbr_flat=_parse_multi_header_table(vbr_div)
    data["backup_server"]={"name":vbr_flat.get("Name",""),"version":vbr_flat.get("Veeam Version",""),
        "os":vbr_flat.get("OS Version",""),
        "config_backup_enabled":_icon_to_bool(vbr_flat.get("Config Backup(CB) Enabled","")),
        "config_backup_last_result":vbr_flat.get("CB Last Result","")}
    data["config_db"]={"type":vbr_flat.get("DataBase Type",""),"server":vbr_flat.get("SQL Server Name",""),
        "version":vbr_flat.get("SQL Version",""),"edition":vbr_flat.get("SQL Edition",""),
        "local":_icon_to_bool(vbr_flat.get("Local SQL",""))}
    ct_div=soup.find("div",id="ComplianceTable")
    compliance={}
    for row in _parse_table(ct_div):
        bp=row.get("Best Practice","").strip(); st=row.get("Status","").strip()
        if bp: compliance[bp]=st
    data["compliance"]=compliance
    ss_div=soup.find("div",id="secsummary")
    sec={}
    for row in _parse_table(ss_div):
        k=list(row.keys())[0] if row else None; v=list(row.values())[0] if row else None
        if k and v: sec[k]=v
    data["security_summary"]=sec
    ms_div=soup.find("div",id="managedServerInfo")
    ms_raw=_parse_table(ms_div)
    skip={"cifsserver","cifsservershare","nasserver","linuxserver"}
    managed=[s for s in ms_raw if s.get("OS Info","").strip() and s.get("Type","").lower() not in skip]
    eol=[]; ws2016=[]
    for s in managed:
        oi=s.get("OS Info",""); nm=s.get("Name","")
        if "2016" in oi: ws2016.append({"name":nm,"os":oi,"type":s.get("Type","")})
        if any(v in oi for v in ["2008","2012","2016"]): eol.append({"name":nm,"os":oi,"eol_risk":True})
    data["managed_servers"]=managed; data["managed_servers_all"]=ms_raw
    data["ws2016_servers"]=ws2016; data["eol_servers"]=eol
    data["proxies"]=_parse_table(soup.find("div",id="proxies"))
    data["repositories"]=_parse_table(soup.find("div",id="repos"))
    data["sobr_extents"]=_parse_table(soup.find("div",id="extents"))
    all_jobs=[]
    for jid in ["jobTable-backup","jobTable-vmware-backup","jobTable-file-backup","jobTable-endpoint-backup",
                "jobTable-nasbackup","jobTable-epagentbackup","jobTable-entra","jobTable-offload"]:
        jdiv=soup.find("div",id=jid); rows=_parse_table(jdiv)
        for r in rows: r["_table"]=jid
        all_jobs.extend(rows)
    data["jobs"]=all_jobs
    mj_div=soup.find("div",id="missingjobs")
    data["missing_job_types"]=[r.get("Type","") for r in _parse_table(mj_div) if r.get("Type")]
    data["protected_workloads"]=_parse_multi_header_table(soup.find("div",id="protectedworkloads"))
    lic_div=soup.find("div",id="licenseInfo") or soup.find("div",id="license")
    data["license"]=_parse_multi_header_table(lic_div) if lic_div else {}
    log.info(f"  VBR: {data['backup_server'].get('name')} v{data['backup_server'].get('version')}")
    log.info(f"  Compliance: {len(compliance)} rules ({sum(1 for v in compliance.values() if v=='Not Implemented')} failed)")
    log.info(f"  Jobs: {len(all_jobs)}  Missing types: {data['missing_job_types']}")
    return data


# ═════════════════════════════════════════════════════════════════════════════
# DOC FETCHER
# ═════════════════════════════════════════════════════════════════════════════

def fetch_veeam_docs(urls=None):
    if urls is None: urls=VEEAM_DOC_URLS
    results={}
    if not REQUESTS_OK:
        return {k:{"url":v,"status":"skipped","text":""} for k,v in urls.items()}
    for key,url in urls.items():
        log.info(f"  Fetching {key}: {url}")
        try:
            r=requests.get(url,headers=FETCH_HEADERS,timeout=20); r.raise_for_status()
            soup=BeautifulSoup(r.text,"html.parser")
            for tag in soup.find_all(["nav","header","footer","script","style"]): tag.decompose()
            content=(soup.find("article") or soup.find("main") or
                     soup.find("div",class_=re.compile(r"content|body|article",re.I)))
            text=content.get_text("\n",strip=True) if content else soup.get_text("\n",strip=True)
            text=re.sub(r"\n{3,}","\n\n",text)
            results[key]={"url":url,"status":"fetched","length":len(text),"text":text[:50000]}
            log.info(f"    {len(text):,} chars")
        except Exception as e:
            log.warning(f"    {key} failed: {e}")
            results[key]={"url":url,"status":"failed","text":""}
    return results

def extract_doc_keywords(docs):
    findings={}
    for doc_type,doc in docs.items():
        text=doc.get("text","").lower()
        if not text: continue
        findings[f"{doc_type}_has_reversed_incremental"]="reversed incremental" in text
        findings[f"{doc_type}_has_sql_2016_req"]="sql server 2016" in text or "sql 2016" in text
        findings[f"{doc_type}_has_cloud_connect_portal"]="cloud connect portal" in text
        findings[f"{doc_type}_has_port_443"]="port 443" in text
        findings[f"{doc_type}_has_upgrade_order"]="upgrade order" in text or "before upgrading" in text
        cves=re.findall(r"CVE-\d{4}-\d+",doc.get("text",""),re.I)
        findings[f"{doc_type}_cve_list"]=list(set(cves))
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# VHC ANALYSIS FUNCTIONS
# ═════════════════════════════════════════════════════════════════════════════

def analyze_upgrade_blockers(vhc):
    results=[]; db=vhc.get("config_db",{}); jobs=vhc.get("jobs",[]); repos=vhc.get("repositories",[])
    for blocker in VEEAM_V13_HARD_BLOCKERS:
        bid=blocker["id"]
        f={"check":blocker["check"],"requirement":blocker["requirement"],"detail":blocker["detail"],"source":blocker["source"]}
        if bid=="sql_version":
            sv=db.get("version","undetermined").lower()
            if sv in ("undetermined","","n/a","—"):
                f["status"]=STATUS_UNKNOWN; f["evidence"]=f"SQL version reported as '{db.get('version')}' — must be manually verified."
                f["action"]=f"Run SELECT @@VERSION on {db.get('server','config DB')} and confirm SQL 2016+ (version 13.x+)."
            elif any(x in sv for x in ["2008","2012","2014"]):
                f["status"]=STATUS_FAIL; f["evidence"]=f"SQL version: {db.get('version')} — below minimum (2016)."
                f["action"]="Upgrade SQL Server to 2016+ before v13 upgrade."
            else:
                f["status"]=STATUS_PASS; f["evidence"]=f"SQL version: {db.get('version')}"; f["action"]=None
        elif bid=="legacy_metadata":
            f["status"]=STATUS_UNKNOWN; f["evidence"]="VHC does not report backup chain metadata format version."
            f["action"]="In VBR: check each job's backup chain properties. If 'Per-VM backup files' is disabled, chain is legacy."
        elif bid=="legacy_backup_copy":
            missing=vhc.get("missing_job_types",[])
            if "Backup Copy" in missing:
                f["status"]=STATUS_PASS; f["evidence"]="No Backup Copy jobs detected."; f["action"]=None
            else:
                bc=[j for j in jobs if "copy" in j.get("Job Type","").lower() or "copy" in j.get("_table","").lower()]
                if bc:
                    f["status"]=STATUS_UNKNOWN; f["evidence"]=f"{len(bc)} Backup Copy job(s) detected. Legacy format (pre-v9) cannot be confirmed from VHC."
                    f["action"]="In VBR: verify each Backup Copy job schedule format. Pre-v9 jobs must be recreated."
                else:
                    f["status"]=STATUS_PASS; f["evidence"]="No Backup Copy jobs found."; f["action"]=None
        elif bid=="cloud_connect_portal":
            cloud_repos=[r for r in repos if "cloud" in r.get("Name","").lower() or r.get("Type","").lower() in ("azure","azurestorage","s3","wasabi")]
            if cloud_repos:
                f["status"]=STATUS_WARN; f["evidence"]=f"{len(cloud_repos)} cloud repo(s) found. Cloud Connect Portal use must be verified."
                f["action"]="Check VBR > Backup Infrastructure > Service Providers."
            else:
                f["status"]=STATUS_PASS; f["evidence"]="No Cloud Connect service providers detected."; f["action"]=None
        elif bid=="veeam_agent_localdb":
            agent_jobs=[j for j in jobs if "endpoint" in j.get("_table","").lower() or "agent" in j.get("Job Type","").lower()]
            if agent_jobs:
                f["status"]=STATUS_WARN; f["evidence"]=f"{len(agent_jobs)} Veeam Agent job(s) found. Agent version (v6+) must be verified."
                f["action"]="Check Inventory > Physical Infrastructure. Confirm all agents show v6.x+."
            else:
                f["status"]=STATUS_PASS; f["evidence"]="No Veeam Agent endpoint backup jobs found."; f["action"]=None
        results.append(f)
    return results

def analyze_deprecated_features(vhc):
    results=[]; jobs=vhc.get("jobs",[])
    reversed_jobs=[j for j in jobs if "reversed" in j.get("Backup Chain Type","").lower()]
    rp_jobs=[j for j in jobs if j.get("Retention Scheme","").lower()=="restore points"]
    non_pm=[j for j in jobs if _icon_to_bool(str(j.get("Per-VM",""))) is False]
    for feat in VEEAM_V13_DEPRECATED_FEATURES:
        fid=feat["id"]
        f={"check":feat["check"],"requirement":feat["requirement"],"detail":feat["detail"]}
        if fid=="reversed_incremental":
            if reversed_jobs:
                f["status"]=STATUS_FAIL; f["evidence"]=f"{len(reversed_jobs)} job(s) use Reversed Incremental: {[j.get('Name','?') for j in reversed_jobs[:5]]}"
                f["action"]="Switch affected jobs to Forward Incremental before upgrading to v13."
            else:
                f["status"]=STATUS_PASS; f["evidence"]=f"All {len(jobs)} jobs use Forward Incremental or other non-reversed types."; f["action"]=None
        elif fid=="restore_point_retention":
            if rp_jobs:
                f["status"]=STATUS_FAIL; f["evidence"]=f"{len(rp_jobs)} job(s) use Restore Points retention: {[j.get('Name','?') for j in rp_jobs[:5]]}"
                f["action"]="Switch affected jobs to Days-based retention before upgrading to v13."
            else:
                f["status"]=STATUS_PASS; f["evidence"]=f"All {len(jobs)} jobs use Days-based retention."; f["action"]=None
        elif fid=="non_per_machine_chains":
            if non_pm:
                f["status"]=STATUS_WARN; f["evidence"]=f"{len(non_pm)} job(s) may not have Per-VM backup files enabled."
                f["action"]="Enable Per-VM backup files on each affected job before upgrading to v13."
            else:
                f["status"]=STATUS_PASS; f["evidence"]="Per-VM backup files enabled across all scanned jobs."; f["action"]=None
        else:
            f["status"]=STATUS_UNKNOWN; f["evidence"]="Cannot be determined from VHC report alone."
            f["action"]=f"Manually verify '{feat['check']}' is not in use in VBR console before upgrading."
        results.append(f)
    return results

def analyze_security_compliance(vhc):
    results=[]; compliance=vhc.get("compliance",{})
    for rule,status in compliance.items():
        f={"rule":rule,"vhc_status":status,
           "v13_relevance":VEEAM_V13_SECURITY_RELEVANCE.get(rule,"LOW — General security best practice.")}
        if status=="Not Implemented":
            sev="HIGH" if f["v13_relevance"].startswith("HIGH") else ("MEDIUM" if f["v13_relevance"].startswith("MEDIUM") else "LOW")
            f["status"]=STATUS_FAIL; f["severity"]=sev; f["action"]=f"Remediate '{rule}' before v13 upgrade."
        else:
            f["status"]=STATUS_PASS; f["severity"]="NONE"; f["action"]=None
        results.append(f)
    return results

def analyze_os_compatibility(vhc):
    results=[]; managed=vhc.get("managed_servers",[]); extents=vhc.get("sobr_extents",[])
    bs_os=vhc.get("backup_server",{}).get("os","")
    if "2016" in bs_os:
        results.append({"component":"Backup Server OS","name":vhc.get("backup_server",{}).get("name","VBR Server"),
            "os":bs_os,"status":STATUS_FAIL,"severity":"HIGH","issue":"Windows Server 2016 — EOL Oct 14, 2025",
            "action":"Upgrade backup server OS to Windows Server 2022 or 2025 before v13 upgrade."})
    eol_map={"2008":"EOL Jan 2020","2012":"EOL Oct 2023","2016":"EOL Oct 2025"}; seen=set()
    for s in managed:
        nm=s.get("Name",""); oi=s.get("OS Info",""); st=s.get("Type","")
        if nm in seen or not oi: continue
        seen.add(nm)
        for ver,eol_note in eol_map.items():
            if ver in oi:
                has_ext=any(nm.lower() in e.get("Specified Gateway(s)","").lower() for e in extents)
                dn=nm.lstrip("\\").strip() or f"Managed Server ({st})"
                results.append({"component":dn,"server_type":st,"os":oi,
                    "status":STATUS_FAIL,"severity":"CRITICAL" if has_ext else "HIGH",
                    "issue":f"Windows Server {ver} — {eol_note}",
                    "refs_risk":"ReFS extent data loss risk (KB2792) — evacuate extents before OS upgrade" if has_ext else "",
                    "action":(f"Evacuate SOBR extents on {dn} first. New-build to WS2025, re-add extents."
                              if has_ext else f"Upgrade {dn} to Windows Server 2025 (requires KB5078752).")})
                break
    for ext in extents:
        if ext.get("Type","").lower()=="windows":
            results.append({"component":"SOBR Extent (Windows/Possible ReFS)","name":ext.get("Name",""),
                "gateway":ext.get("Specified Gateway(s)",""),"path":ext.get("Path",""),
                "status":STATUS_WARN,"severity":"MEDIUM","issue":"Windows extent — verify filesystem type (NTFS vs ReFS)",
                "action":"If ReFS: evacuate extent before any OS upgrade (KB2792). Do NOT perform in-place OS upgrade with active ReFS extents."})
    return results

def analyze_coverage_gaps(vhc):
    results=[]; missing=vhc.get("missing_job_types",[]); pw=vhc.get("protected_workloads",{})
    critical_missing={"Backup Copy":"No offsite copy jobs — violates 3-2-1 backup rule.",
        "SureBackup":"No recovery verification jobs.",
        "Replica":"No replication jobs.",
        "CDP":"No Continuous Data Protection jobs."}
    for jtype,detail in critical_missing.items():
        if jtype in missing:
            results.append({"gap":f"No {jtype} jobs configured",
                "status":STATUS_FAIL if jtype=="Backup Copy" else STATUS_WARN,"detail":detail,
                "action":f"Implement Backup Copy to secondary/cloud target immediately." if jtype=="Backup Copy" else f"Configure {jtype} jobs post v13 upgrade."})
    vi_not_prot=int(re.sub(r"[^\d]","",pw.get("Vi Not Prot","0")) or 0)
    if vi_not_prot>0:
        results.append({"gap":f"{vi_not_prot} VMware VMs not protected","status":STATUS_FAIL,
            "detail":f"{vi_not_prot} VMs in inventory have no backup job coverage.",
            "action":"Add unprotected VMs to existing jobs or create new jobs."})
    phys_not_prot=int(re.sub(r"[^\d]","",pw.get("Phys Not Prot","0")) or 0)
    if phys_not_prot>0:
        results.append({"gap":f"{phys_not_prot} physical server(s) not protected","status":STATUS_FAIL,
            "detail":f"{phys_not_prot} physical servers have no Veeam Agent backup coverage.",
            "action":"Deploy Veeam Agent and configure backup jobs."})
    return results

def analyze_workload_incompatibilities(vhc):
    results=[]
    for incompat in WORKLOAD_INCOMPATIBILITIES:
        f=dict(incompat)
        if incompat["component"]=="SQL Server 2025":
            f["status"]=STATUS_WARN; f["evidence"]="Cannot confirm SQL 2025 instances from VHC alone."
            f["action"]="Audit all SQL Server instances. Any SQL 2025 must not be targeted by Veeam v12 transaction log jobs."
        elif incompat["component"]=="Windows Server 2016":
            ws2016=vhc.get("ws2016_servers",[])
            if ws2016:
                f["status"]=STATUS_FAIL; f["evidence"]=f"{len(ws2016)} WS2016 server(s) detected."
                f["action"]="Upgrade all WS2016 servers. For servers with ReFS extents: evacuate first, then new-build to WS2025."
            else:
                f["status"]=STATUS_PASS; f["evidence"]="No WS2016 servers detected."; f["action"]=None
        elif incompat["component"]=="ReFS volumes (in-place OS upgrade)":
            win_ext=[e for e in vhc.get("sobr_extents",[]) if e.get("Type","").lower()=="windows"]
            if win_ext:
                f["status"]=STATUS_WARN; f["evidence"]=f"{len(win_ext)} Windows-type SOBR extent(s) found."
                f["action"]="For any ReFS extent: evacuate data before OS upgrade. Never in-place upgrade with active ReFS extents."
            else:
                f["status"]=STATUS_PASS; f["evidence"]="No Windows-type SOBR extents found."; f["action"]=None
        elif incompat["component"]=="Veeam ONE / Enterprise Manager":
            f["status"]=STATUS_WARN; f["evidence"]="Upgrade order risk applies to any environment with Veeam ONE or Enterprise Manager."
            f["action"]="Upgrade order: Veeam ONE → Enterprise Manager → VBR."
        else:
            f["status"]=STATUS_UNKNOWN; f["evidence"]="Manual verification required."; f["action"]=incompat.get("detail","")
        results.append(f)
    return results

def analyze_rvtools(vhc, rvtools):
    if not rvtools or rvtools.get("error"):
        return [{"check":"RVTools data","status":STATUS_UNKNOWN,
            "evidence":f"RVTools file could not be parsed: {rvtools.get('error','no data') if rvtools else 'not provided'}",
            "action":"Provide a valid RVTools xlsx export to enable VM inventory cross-referencing."}]
    results=[]; vms=rvtools.get("non_templates", rvtools.get("vinfo",[])); datastores=rvtools.get("datastores", rvtools.get("vdatastore",[]))
    powered_on=[v for v in vms if v.get("powerstate")=="poweredOn"]
    powered_off=[v for v in vms if v.get("powerstate")=="poweredOff"]
    templates=rvtools.get("templates",[])
    results.append({"check":"RVTools VM inventory","status":STATUS_PASS,
        "evidence":f"{len(vms)+len(templates)} total: {len(vms)} VMs ({len(powered_on)} on, {len(powered_off)} off), {len(templates)} templates.",
        "action":None})
    needs_cons=[v for v in vms if v.get("consolidation_needed")]
    if needs_cons:
        results.append({"check":"VM consolidation required","status":STATUS_FAIL,"severity":"HIGH",
            "evidence":f"{len(needs_cons)} VM(s) have 'Consolidation Needed' flagged: "+", ".join(v["name"] for v in needs_cons[:8])+(" …" if len(needs_cons)>8 else ""),
            "action":"Consolidate before upgrading to Veeam v13. In vCenter: right-click VM → Snapshots → Consolidate."})
    else:
        results.append({"check":"VM consolidation required","status":STATUS_PASS,"evidence":"No VMs flagged as needing consolidation.","action":None})
    pw=vhc.get("protected_workloads",{})
    vi_prot=int(re.sub(r"[^\d]","",str(pw.get("Vi Protected","0"))) or 0)
    vi_not_prot=int(re.sub(r"[^\d]","",str(pw.get("Vi Not Prot","0"))) or 0)
    delta=len(powered_on)-vi_prot if vi_prot else 0
    if delta>5:
        results.append({"check":"VM protection gap (RVTools vs VHC)","status":STATUS_WARN,"severity":"MEDIUM",
            "evidence":f"RVTools: {len(powered_on)} powered-on VMs; VHC: {vi_prot} protected ({vi_not_prot} unprotected). Delta: {delta}.",
            "action":"Review VMs in RVTools not in VBR inventory. Add missing VMs to backup jobs."})
    elif vi_not_prot>0:
        results.append({"check":"VM protection gap (RVTools vs VHC)","status":STATUS_WARN,"severity":"MEDIUM",
            "evidence":f"VHC reports {vi_not_prot} unprotected VMs. RVTools confirms {len(powered_on)} powered-on.",
            "action":"Add unprotected VMs to backup jobs before v13 upgrade."})
    else:
        results.append({"check":"VM protection gap (RVTools vs VHC)","status":STATUS_PASS,
            "evidence":f"RVTools: {len(powered_on)} powered-on. VHC: {vi_prot} protected. No material gap.","action":None})
    eol_guests=[]
    for v in [x for x in vms if not x.get("template")]:
        os_str=v.get("os","")
        if any(p.lower() in os_str.lower() for p in EOL_GUEST_PATTERNS): eol_guests.append({"name":v["name"],"os":os_str})
    if eol_guests:
        results.append({"check":"EOL guest OS in VM inventory","status":STATUS_WARN,"severity":"MEDIUM",
            "evidence":f"{len(eol_guests)} VM(s) running EOL guest OS: "+"; ".join(f"{g['name']} ({g['os']})" for g in eol_guests[:6])+(" …" if len(eol_guests)>6 else ""),
            "action":"EOL guest OS receives no security patches. App-aware processing may be unreliable."})
    else:
        results.append({"check":"EOL guest OS in VM inventory","status":STATUS_PASS,
            "evidence":f"No common EOL guest OS patterns detected across {len(vms)} VMs.","action":None})
    crit_ds=[d for d in datastores if d.get("used_pct",0)>=DS_CRIT_PCT]
    warn_ds=[d for d in datastores if DS_WARN_PCT<=d.get("used_pct",0)<DS_CRIT_PCT]
    if crit_ds:
        results.append({"check":"Datastore capacity — CRITICAL","status":STATUS_FAIL,"severity":"CRITICAL",
            "evidence":f"{len(crit_ds)} datastore(s) over {DS_CRIT_PCT}% full: "+"; ".join(f"{d['name']} ({d['used_pct']}%, {d.get('free_gib',d.get('free_gb',0))} GiB free)" for d in crit_ds[:5]),
            "action":"Datastores over 92% full can cause Veeam snapshot commits to fail. Free space before upgrading."})
    if warn_ds:
        results.append({"check":f"Datastore capacity — over {DS_WARN_PCT}%","status":STATUS_WARN,"severity":"MEDIUM",
            "evidence":f"{len(warn_ds)} datastore(s) between {DS_WARN_PCT}–{DS_CRIT_PCT}% full: "+"; ".join(f"{d['name']} ({d['used_pct']}%)" for d in warn_ds[:5]),
            "action":f"Veeam BP recommends ≥{100-DS_WARN_PCT}% free on datastores hosting backed-up VMs."})
    if not crit_ds and not warn_ds:
        total_cap=round(sum(d.get("cap_gib",d.get("capacity_gb",0)) for d in datastores),1)
        total_free=round(sum(d.get("free_gib",d.get("free_gb",0)) for d in datastores),1)
        results.append({"check":"Datastore capacity","status":STATUS_PASS,
            "evidence":f"All {len(datastores)} datastores below {DS_WARN_PCT}% utilisation. Total: {total_cap} GiB capacity, {total_free} GiB free.","action":None})
    return results


# ═════════════════════════════════════════════════════════════════════════════
# RVTOOLS BEST-PRACTICE GAP ANALYSIS  (standalone, no VHC required)
# ═════════════════════════════════════════════════════════════════════════════

def _os_breakdown(vms):
    counts={}
    for v in vms:
        os_str=v.get("os","") or "Unknown"
        if re.search(r"windows server 2025",os_str,re.I): key="Windows Server 2025"
        elif re.search(r"windows server 2022",os_str,re.I): key="Windows Server 2022"
        elif re.search(r"windows server 2019",os_str,re.I): key="Windows Server 2019"
        elif re.search(r"windows server 2016",os_str,re.I): key="Windows Server 2016 ⚠"
        elif re.search(r"windows server 2012",os_str,re.I): key="Windows Server 2012 (EOL)"
        elif re.search(r"windows server 2008",os_str,re.I): key="Windows Server 2008 (EOL)"
        elif re.search(r"windows 10|windows 11",os_str,re.I): key="Windows Desktop"
        elif re.search(r"red hat|rhel",os_str,re.I): key=os_str[:40]
        elif re.search(r"ubuntu",os_str,re.I):
            m=re.search(r"ubuntu[\s\d.]+",os_str,re.I); key=m.group(0).strip()[:30] if m else "Ubuntu"
        elif re.search(r"centos",os_str,re.I):
            m=re.search(r"centos[\s\d.]+",os_str,re.I); key=m.group(0).strip()[:30] if m else "CentOS"
        elif re.search(r"suse|sles",os_str,re.I): key="SUSE Linux"
        elif not os_str or os_str.lower() in ("unknown","none",""): key="Unknown"
        else: key=os_str[:45]
        counts[key]=counts.get(key,0)+1
    return dict(sorted(counts.items(),key=lambda x:-x[1]))

def _cluster_summary(vms, hosts):
    clusters={}
    for v in vms:
        c=v.get("cluster") or "Standalone"
        if c not in clusters: clusters[c]={"name":c,"vms":0,"powered_on":0,"cpu_total":0,"mem_gib":0.0}
        clusters[c]["vms"]+=1
        if v.get("powerstate")=="poweredOn": clusters[c]["powered_on"]+=1
        clusters[c]["cpu_total"]+=v.get("cpu",0); clusters[c]["mem_gib"]+=v.get("memory_gib",0)
    hbc={}
    for h in hosts:
        c=h.get("cluster") or "Standalone"; hbc.setdefault(c,[]).append(h)
    result=[]
    for cname,cdata in sorted(clusters.items(),key=lambda x:-x[1]["vms"]):
        ch=hbc.get(cname,[]); cdata["host_count"]=len(ch)
        cdata["host_cores"]=sum(h.get("cores",0) for h in ch)
        cdata["host_mem_gib"]=round(sum(h.get("memory_gib",0) for h in ch),1)
        cdata["mem_gib"]=round(cdata["mem_gib"],1); result.append(cdata)
    return result

def _vendor_summary(datastores):
    s={}
    for d in datastores:
        v=d["vendor"]
        if v not in s: s[v]={"count":0,"cap_gib":0.0,"free_gib":0.0}
        s[v]["count"]+=1; s[v]["cap_gib"]+=d["cap_gib"]; s[v]["free_gib"]+=d["free_gib"]
    return {v:{k:round(val,1) if isinstance(val,float) else val for k,val in stats.items()} for v,stats in s.items()}

def _esxi_breakdown(hosts):
    counts={}
    for h in hosts:
        ver=h.get("esxi_ver","Unknown"); counts[ver]=counts.get(ver,0)+1
    return dict(sorted(counts.items(),key=lambda x:x[0],reverse=True))

def _bp_gaps(rv, docs):
    gaps=[]; vms=rv.get("non_templates",[]); powered=rv.get("powered_on",[]); datastores=rv.get("datastores",[])
    hosts=rv.get("hosts",[]); snapshots=rv.get("snapshots",[])
    consolidate=[v for v in vms if v.get("consolidation_needed")]
    if consolidate:
        gaps.append({"status":"FAIL","severity":"HIGH","check":"VM consolidation required",
            "detail":f"{len(consolidate)} VM(s) have uncommitted snapshot delta files: "+", ".join(v["name"] for v in consolidate[:6])+(" …" if len(consolidate)>6 else ""),
            "action":"Consolidate via vCenter → right-click VM → Snapshots → Consolidate before running Veeam backups.",
            "ref":"Veeam BP: snapshot consolidation must complete before backup to avoid CBT reset."})
    if snapshots:
        old_snaps=[]
        for s in snapshots:
            try:
                created=datetime.fromisoformat(str(s["created"]).split("T")[0])
                age=(datetime.now()-created).days
                if age>7: old_snaps.append((s["vm"],age,s.get("size_gib",0)))
            except: old_snaps.append((s["vm"],999,s.get("size_gib",0)))
        if old_snaps:
            gaps.append({"status":"WARN","severity":"MEDIUM","check":f"Stale VM snapshots ({len(old_snaps)})",
                "detail":f"{len(old_snaps)} snapshot(s) older than 7 days. Largest: "+", ".join(f"{vm} ({age}d, {gib:.1f} GiB)" for vm,age,gib in old_snaps[:4]),
                "action":"Remove stale snapshots. Full datastores cause Veeam backup failures.",
                "ref":"bp.veeam.com/vbr — snapshot management; Veeam KB2093."})
    crit_ds=[d for d in datastores if d["used_pct"]>=DS_CRIT_PCT]
    warn_ds=[d for d in datastores if DS_WARN_PCT<=d["used_pct"]<DS_CRIT_PCT]
    if crit_ds:
        gaps.append({"status":"FAIL","severity":"CRITICAL","check":f"Datastores critically full (>{DS_CRIT_PCT}%)",
            "detail":"; ".join(f"{d['name']} ({d['used_pct']}%, {d['free_gib']:.1f} GiB free / {d['cap_gib']:.1f} GiB)" for d in crit_ds[:5]),
            "action":"Free space or expand datastores. Veeam snapshot delta files require temporary space.",
            "ref":f"bp.veeam.com/vbr: maintain ≥{100-DS_CRIT_PCT}% free space on datastores hosting backed-up VMs."})
    if warn_ds:
        gaps.append({"status":"WARN","severity":"MEDIUM","check":f"Datastores approaching capacity ({DS_WARN_PCT}–{DS_CRIT_PCT}%)",
            "detail":"; ".join(f"{d['name']} ({d['used_pct']}%, {d['free_gib']:.1f} GiB free)" for d in warn_ds[:5]),
            "action":f"Monitor — Veeam BP recommends >{100-DS_WARN_PCT}% free on datastores with backed-up VMs.",
            "ref":"bp.veeam.com/vbr — infrastructure planning."})
    eol_vms=[v["name"] for v in powered if any(p.lower() in v.get("os","").lower() for p in EOL_GUEST_PATTERNS)]
    if eol_vms:
        gaps.append({"status":"WARN","severity":"MEDIUM","check":f"EOL guest OS on {len(eol_vms)} powered-on VM(s)",
            "detail":", ".join(eol_vms[:8])+(" …" if len(eol_vms)>8 else ""),
            "action":"EOL OS has no security patches. Plan OS upgrades.",
            "ref":"helpcenter.veeam.com/docs/vbr/userguide — guest OS support matrix."})
    esxi_eol=[h for h in hosts if h.get("esxi_ver","").startswith(("5.","6."))]
    if esxi_eol:
        gaps.append({"status":"WARN","severity":"MEDIUM","check":f"ESXi EOL version on {len(esxi_eol)} host(s)",
            "detail":"; ".join(f"{h['name']} (ESXi {h['esxi_ver']})" for h in esxi_eol[:6]),
            "action":"Upgrade ESXi to 7.x (minimum for Veeam v13) or 8.x (recommended).",
            "ref":"helpcenter.veeam.com/rn/veeam_backup_13_0_2_release_notes — vSphere 6.5 U3 minimum."})
    tools_old=[v for v in powered if "not current" in v.get("tools_status","").lower() or "out of date" in v.get("tools_status","").lower()]
    if tools_old:
        gaps.append({"status":"WARN","severity":"LOW","check":f"VMware Tools not current on {len(tools_old)} VM(s)",
            "detail":", ".join(v["name"] for v in tools_old[:8])+(" …" if len(tools_old)>8 else ""),
            "action":"Update VMware Tools. Required for quiesced snapshots and app-aware processing.",
            "ref":"bp.veeam.com/vbr — VMware Tools must be current for reliable Veeam VSS quiescing."})
    tools_none=[v for v in powered if "not installed" in v.get("tools_status","").lower()]
    if tools_none:
        gaps.append({"status":"WARN","severity":"MEDIUM","check":f"VMware Tools not installed on {len(tools_none)} VM(s)",
            "detail":", ".join(v["name"] for v in tools_none[:6])+(" …" if len(tools_none)>6 else ""),
            "action":"Without Tools, Veeam cannot quiesce the guest — backups are crash-consistent only.",
            "ref":"bp.veeam.com/vbr — application-aware image processing requires VMware Tools."})
    if not gaps:
        gaps.append({"status":"PASS","severity":"NONE","check":"No critical gaps detected from RVTools data",
            "detail":"All key RVTools checks passed.","action":None,"ref":None})
    return gaps


# ═════════════════════════════════════════════════════════════════════════════
# SVG ARCHITECTURE DIAGRAM
# ═════════════════════════════════════════════════════════════════════════════

def _bool_icon(val):
    s=str(val).strip().lower()
    return "✅" if s in ("true","yes","✅","1","passed","enabled") else "☐"

def _repo_color(t):
    t=t.lower()
    if "hardened" in t: return "#00695c"
    if "linux" in t: return "#2e7d32"
    if "ddboost" in t or "datadomain" in t: return "#1565c0"
    if "win" in t: return "#6a1b9a"
    if "s3" in t or "azure" in t or "wasabi" in t or "object" in t: return "#0277bd"
    if "sobr" in t: return "#e65100"
    return "#555"

def _repo_label(t):
    t=t.lower()
    if "hardened" in t: return "Hardened Linux"
    if "linuxlocal" in t or "linux" in t: return "Linux Repo"
    if "ddboost" in t: return "DDBoost"
    if "winlocal" in t or "win" in t: return "Windows Repo"
    if "s3" in t: return "S3 Object"
    if "azure" in t: return "Azure Blob"
    if "wasabi" in t: return "Wasabi"
    if "sobr" in t: return "SOBR"
    return t or "Repository"

def _proxy_color(t):
    t=t.lower()
    if "vmware" in t or "vi" in t: return "#0077aa"
    if "file" in t: return "#4a9fd4"
    if "nas" in t: return "#6d9e3f"
    return "#0077aa"

_SVG_DEFS="""
  <defs>
    <marker id="ab" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#005b99"/></marker>
    <marker id="ag" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#888"/></marker>
    <marker id="ao" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#c05c00"/></marker>
    <filter id="sh" x="-5%" y="-5%" width="120%" height="120%"><feDropShadow dx="0" dy="2" stdDeviation="2.5" flood-color="#00000025"/></filter>
  </defs>"""

def _box(x,y,w,h,stroke,fill="white",rx=6,shadow=True):
    f='filter="url(#sh)"' if shadow else ""
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="1.5" {f}/>'

def _header_bar(x,y,w,h,color,rx=6):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{color}"/>'
            f'<rect x="{x}" y="{y+rx}" width="{w}" height="{h-rx}" fill="{color}"/>')

def _svgtext(x,y,s,size=11,color="#222",weight="normal",anchor="start"):
    return f'<text x="{x}" y="{y}" fill="{color}" font-size="{size}" font-weight="{weight}" text-anchor="{anchor}">{_esc(s)}</text>'

def _svg_badge(x,y,label,color,w=None):
    w=w or max(60,len(label)*7+14)
    return (f'<rect x="{x}" y="{y}" width="{w}" height="16" rx="8" fill="{color}"/>'
            f'<text x="{x+w//2}" y="{y+11}" fill="white" font-size="9" font-weight="700" text-anchor="middle">{_esc(label)}</text>')

def _warn_box(x,y,w,h,lines_):
    out=[f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="4" fill="#fff8e6" stroke="#e67e22" stroke-width="1.5"/>']
    for i,ln in enumerate(lines_): out.append(_svgtext(x+8,y+15+i*16,ln,size=9,color="#444"))
    return "\n".join(out)

def _zone(x,y,w,h,hc,label,icon=""):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="#f8faff" stroke="{hc}" stroke-width="1.5" stroke-dasharray="6,3"/>'
            f'<rect x="{x}" y="{y}" width="{w}" height="24" rx="8" fill="{hc}"/>'
            f'<rect x="{x}" y="{y+16}" width="{w}" height="8" fill="{hc}"/>'
            +_svgtext(x+w//2,y+15,f"{icon}  {label}",11,"white","700","middle"))

def _classify_env(vhc, rvtools):
    vm_count=0
    if rvtools and not rvtools.get("error"):
        vm_count=sum(1 for v in rvtools.get("non_templates",rvtools.get("vinfo",[]))
                     if not v.get("template") and v.get("powerstate")=="poweredOn")
    if vm_count==0:
        pw=vhc.get("protected_workloads",{})
        vm_count=int(re.sub(r"[^\d]","",str(pw.get("Vi Protected","0"))) or 0)
    proxies=vhc.get("proxies",[]); repos=vhc.get("repositories",[]); extents=vhc.get("sobr_extents",[]); missing=vhc.get("missing_job_types",[])
    tier="small" if vm_count<_ENV_SMALL else ("medium" if vm_count<_ENV_MEDIUM else "large")
    recommended_proxies=max(2,math.ceil(vm_count/_VMS_PER_PROXY)) if vm_count else 2
    hardened=[r for r in repos if "hardened" in r.get("Type","").lower() or "immut" in r.get("Type","").lower()]
    object_repos=[r for r in repos if any(x in r.get("Type","").lower() for x in ("s3","azure","wasabi","object","cloud"))]
    return {"vm_count":vm_count,"tier":tier,"proxies":proxies,"proxy_count":len(proxies),
        "recommended_proxies":recommended_proxies,"repos":repos,"hardened_repos":hardened,
        "object_repos":object_repos,"extents":extents,"has_sobr":bool(extents),
        "has_backup_copy":"Backup Copy" not in missing,"has_surebackup":"SureBackup" not in missing,
        "has_cdp":"CDP" not in missing,"missing_jobs":missing,
        "vbr_name":vhc.get("backup_server",{}).get("name","VBR Server"),
        "vbr_version":vhc.get("backup_server",{}).get("version",""),
        "vbr_os":vhc.get("backup_server",{}).get("os","")}

def _build_svg_header(env,vhc,report):
    bs=vhc.get("backup_server",{}); lic=vhc.get("license",{}); pw=vhc.get("protected_workloads",{})
    vi_p=re.sub(r"[^\d]","",str(pw.get("Vi Protected","0"))) or "0"
    vi_n=re.sub(r"[^\d]","",str(pw.get("Vi Not Prot","0"))) or "0"
    vi_t=re.sub(r"[^\d]","",str(pw.get("Vi Total","0"))) or "0"
    smry=report.get("summary",{}); fail=smry.get("FAIL",0); warn=smry.get("WARN",0); ok=smry.get("PASS",0)
    site=Path(report.get("meta",{}).get("vhc_file","")).stem or "VBR"
    ver=_esc(bs.get("version","")); ed=_esc(lic.get("Edition","")); used=_esc(lic.get("Used Inst.","")); tot=_esc(lic.get("Licensed Inst.","")); exp=_esc(lic.get("Exp Date",""))
    return (f'<rect width="1360" height="72" fill="#005b99"/>'
            f'<rect y="68" width="1360" height="4" fill="#00b050"/>'
            f'<polygon points="18,12 40,12 56,58 72,12 94,12 56,64 18,12" fill="white" opacity=".9"/>'
            +_svgtext(108,32,site.upper()+"  —  Veeam Backup Architecture",18,"white","700")
            +_svgtext(108,52,f"VBR v{ver}  ·  {ed} Edition  ·  {used}/{tot} licenses  ·  Exp: {exp}",12,"#b8d8f0")
            +f'<rect x="800" y="10" width="72" height="50" rx="5" fill="#1a4a20"/>'
            +_svgtext(836,28,"Protected",9,"#aaa",anchor="middle")+_svgtext(836,46,vi_p,18,"#69db7c","700","middle")
            +f'<rect x="880" y="10" width="72" height="50" rx="5" fill="#4a1515"/>'
            +_svgtext(916,28,"Unprotected",9,"#aaa",anchor="middle")+_svgtext(916,46,vi_n,18,"#ff8080","700","middle")
            +f'<rect x="960" y="10" width="72" height="50" rx="5" fill="#222"/>'
            +_svgtext(996,28,"Total VMs",9,"#aaa",anchor="middle")+_svgtext(996,46,vi_t,18,"#ccc","700","middle")
            +f'<rect x="1040" y="10" width="72" height="50" rx="5" fill="#4a1515"/>'
            +_svgtext(1076,28,"FAIL",9,"#aaa",anchor="middle")+_svgtext(1076,46,str(fail),18,"#ff8080","700","middle")
            +f'<rect x="1120" y="10" width="72" height="50" rx="5" fill="#3a3000"/>'
            +_svgtext(1156,28,"WARN",9,"#aaa",anchor="middle")+_svgtext(1156,46,str(warn),18,"#ffa94d","700","middle")
            +f'<rect x="1200" y="10" width="72" height="50" rx="5" fill="#0d3320"/>'
            +_svgtext(1236,28,"PASS",9,"#aaa",anchor="middle")+_svgtext(1236,46,str(ok),18,"#69db7c","700","middle")
            +f'<rect x="1280" y="10" width="68" height="50" rx="5" fill="#1a3a5c"/>'
            +_svgtext(1314,28,"v13 Ready",9,"#aaa",anchor="middle")
            +_svgtext(1314,46,"NO" if fail>0 else "YES",18,"#ff8080" if fail>0 else "#69db7c","700","middle"))

def _build_vsphere_zone(vhc, env, rvtools):
    parts=[]; ox,oy=14,84; zw=428
    y=oy+32
    for vc in [s for s in vhc.get("managed_servers_all",[]) if s.get("Type","").upper() in ("VC","VCENTER")][:2]:
        vcn=_esc(vc.get("Name","vCenter")); osv=_esc(vc.get("OS Info",""))
        parts+=[_box(ox+10,y,zw-20,88,"#1a7a3c"),_header_bar(ox+10,y,zw-20,18,"#1a7a3c"),
                _svgtext(ox+zw//2,y+13,vcn,10,"white","700","middle"),
                _svgtext(ox+18,y+34,osv[:52] if osv else "VMware vCenter",10,"#555"),
                _svgtext(ox+18,y+50,f"VMs: {vc.get('Protected VMs','?')} protected  /  {vc.get('Total VMs','?')} total",10,"#555"),
                _svgtext(ox+18,y+66,f"",9,"#aaa")]
        y+=96
    all_managed=vhc.get("managed_servers_all",[]); esxi_hosts=[s for s in all_managed if s.get("Type","").upper()=="ESXI"]
    ver_groups={}
    for h in esxi_hosts:
        m=re.search(r"ESXi\s+([\d.]+)",h.get("OS Info","")); ver=m.group(1) if m else "Unknown"
        ver_groups.setdefault(ver,[]).append(h)
    rv_clusters={}
    if rvtools and not rvtools.get("error"):
        for row in rvtools.get("hosts",rvtools.get("vhost",[])):
            cname=str(row.get("cluster") or row.get("Cluster") or "Standalone")
            rv_clusters.setdefault(cname,{"hosts":0,"cores":0,"ram_gb":0})
            rv_clusters[cname]["hosts"]+=1
            rv_clusters[cname]["cores"]+=int(row.get("cores") or row.get("# Cores") or 0)
            mem_v=row.get("memory_gib",0) or 0
            if not mem_v:
                try: mem_v=round(float(str(row.get("# Memory",0) or 0))/1024,1)
                except: mem_v=0
            rv_clusters[cname]["ram_gb"]+=mem_v
    if rv_clusters:
        parts+=[_box(ox+10,y,zw-20,24+len(rv_clusters)*38,"#3a6db5"),_header_bar(ox+10,y,zw-20,12,"#3a6db5"),
                _svgtext(ox+zw//2,y+9,"vSphere Clusters  (from RVTools)",10,"white","700","middle")]
        cy=y+18
        for cname,cd in sorted(rv_clusters.items()):
            parts+=[_box(ox+18,cy,zw-36,32,"#5a8fd5",fill="#f4f8ff",shadow=False),
                    _svgtext(ox+28,cy+13,f"⬡ {_esc(cname)}",10,"#1a3a5c","700"),
                    _svgtext(ox+28,cy+25,f"{cd['hosts']} hosts  ·  {cd['cores']} cores  ·  {cd['ram_gb']:.0f} GiB RAM",9,"#555")]
            cy+=36
        y+=24+len(rv_clusters)*38+8
    elif ver_groups:
        row_h=26
        parts+=[_box(ox+10,y,zw-20,20+len(ver_groups)*row_h,"#555"),_header_bar(ox+10,y,zw-20,10,"#555"),
                _svgtext(ox+zw//2,y+8,f"ESXi Hosts Managed  ({len(esxi_hosts)} total)",10,"white","700","middle")]
        vy=y+16
        for ver,hosts_v in sorted(ver_groups.items(),reverse=True):
            major=ver.split(".")[0] if ver else "?"
            color={"8":"#27ae60","7":"#e67e22"}.get(major,"#c0392b")
            label={"8":"Current","7":"Supported"}.get(major,"⚠ EOL")
            parts+=[_svgtext(ox+20,vy+14,f"ESXi {ver}",11,color,"700"),_svgtext(ox+130,vy+14,f"{len(hosts_v)} hosts  —  {label}",10,"#555")]
            vy+=row_h
        y+=20+len(ver_groups)*row_h+8
    pw=vhc.get("protected_workloads",{})
    vi_p=int(re.sub(r"[^\d]","",str(pw.get("Vi Protected","0"))) or 0)
    vi_t=int(re.sub(r"[^\d]","",str(pw.get("Vi Total","0"))) or 1)
    vi_n=int(re.sub(r"[^\d]","",str(pw.get("Vi Not Prot","0"))) or 0)
    pct=round(vi_p/vi_t*100) if vi_t else 0; bar_w=zw-40; prot_w=max(2,round(bar_w*pct/100))
    parts+=[_box(ox+10,y,zw-20,62,"#aaa",fill="#fff",shadow=False),
            _svgtext(ox+20,y+14,"VM Backup Coverage",10,"#333","700"),
            _svgtext(ox+20,y+28,f"{vi_p} protected",10,"#27ae60","700"),
            _svgtext(ox+130,y+28,f"{vi_n} unprotected",10,"#c0392b","700"),
            _svgtext(ox+260,y+28,f"{vi_t} total",10,"#555"),
            f'<rect x="{ox+20}" y="{y+34}" width="{bar_w}" height="10" rx="5" fill="#eee"/>',
            f'<rect x="{ox+20}" y="{y+34}" width="{prot_w}" height="10" rx="5" fill="#27ae60"/>',
            f'<rect x="{ox+20+prot_w}" y="{y+34}" width="{bar_w-prot_w}" height="10" rx="0" fill="#e74c3c"/>',
            _svgtext(ox+20,y+56,f"{pct}% protected",9,"#555")]
    y+=70
    zone_h=y-oy+20
    return _zone(ox,oy,zw,zone_h,"#4a6e8f","PRODUCTION  —  vSPHERE ENVIRONMENT","⬡")+"\n"+"\n".join(str(p) for p in parts), zone_h

def _build_veeam_zone(vhc, env, report):
    parts=[]; ox,oy=458,84; zw=418
    y=oy+32; bs=vhc.get("backup_server",{}); db=vhc.get("config_db",{})
    bsn=_esc(bs.get("name","Backup Server")); bsv=_esc(bs.get("version","")); bso=_esc(bs.get("os",""))
    all_managed=vhc.get("managed_servers_all",[]); bs_entry=next((s for s in all_managed if s.get("Name","")==bs.get("name","")),{})
    is_proxy=bs_entry.get("Is Proxy","") in ("✅","True","true"); is_repo=bs_entry.get("Is Repo","") in ("✅","True","true")
    bs_cores=bs_entry.get("Cores","?"); bs_ram=bs_entry.get("RAM","?")
    roles=["BACKUP SERVER"]
    if is_proxy: roles.append("PROXY")
    if is_repo: roles.append("GATEWAY/REPO")
    multi_role_warn=len(roles)>1; bs_h=140 if not multi_role_warn else 176
    parts+=[_box(ox+10,y,zw-20,bs_h,"#005b99"),_header_bar(ox+10,y,zw-20,18,"#005b99"),
            f'<rect x="{ox+18}" y="{y+26}" width="40" height="40" rx="6" fill="#005b99"/>',
            _svgtext(ox+38,y+42,"VBR",9,"white","700","middle"),_svgtext(ox+38,y+54,"SERVER",8,"white",anchor="middle"),
            _svgtext(ox+68,y+36,bsn,13,"#1a1a3a","700"),
            _svgtext(ox+68,y+52,f"Veeam Backup & Replication  v{bsv}",10,"#005b99","600"),
            _svgtext(ox+68,y+68,f"{bso}  ·  {bs_cores} cores  ·  {bs_ram} GB RAM",10,"#555")]
    bx=ox+18
    for role in roles:
        rc={"BACKUP SERVER":"#005b99","PROXY":"#0077aa","GATEWAY/REPO":"#3a6090"}.get(role,"#555")
        parts.append(_svg_badge(bx,y+82,role,rc)); bx+=len(role)*7+22
    if multi_role_warn:
        parts.append(_warn_box(ox+18,y+102,zw-36,62,["⚠  Server is running multiple roles — review sizing before upgrade.",
            f"     Cores: {bs_cores} available  (may be insufficient for combined load)","     Recommend: dedicated proxy + separate gateway server."]))
    db_ver=db.get("version",""); db_srv=db.get("server","")
    db_color="#c0392b" if not db_ver else "#555"
    db_note="Not detected — verify SQL 2016+!" if not db_ver else f"{db.get('type','')}  {db_ver}"
    parts+=[_svgtext(ox+18,y+bs_h+14,"Config DB:",10,"#333","700"),_svgtext(ox+88,y+bs_h+14,f"{_esc(db_srv)}  {_esc(db_note)}",10,db_color)]
    y+=bs_h+28
    proxies=vhc.get("proxies",[])
    if proxies:
        # Group proxies by type for compact summary
        type_counts={}
        for px in proxies:
            t=px.get("Proxy Type","Unknown"); type_counts[t]=type_counts.get(t,0)+1
        n_types=max(len(type_counts),1)
        panel_h=130
        parts+=[_box(ox+10,y,zw-20,panel_h,"#0077aa"),_header_bar(ox+10,y,zw-20,18,"#0077aa"),
                _svgtext(ox+zw//2,y+13,f"Backup Proxies  ({len(proxies)})",10,"white","700","middle")]
        # Large count centred
        parts.append(_svgtext(ox+zw//2,y+66,str(len(proxies)),42,"#1a1a3a","700","middle"))
        parts.append(_svgtext(ox+zw//2,y+83,"total proxies",10,"#555",anchor="middle"))
        # Per-type breakdown tiles
        tile_w=(zw-36)//n_types-6; tx=ox+18
        for ptype,cnt in sorted(type_counts.items()):
            pc=_proxy_color(ptype)
            parts+=[_box(tx,y+92,tile_w,28,pc,fill="#f0f7ff",shadow=False),
                    _svgtext(tx+6,y+104,f"{cnt}×",11,"#1a3a5c","700"),
                    _svgtext(tx+24,y+104,ptype[:16],9,"#555"),
                    _svgtext(tx+6,y+116,"proxies",8,"#888")]
            tx+=tile_w+6
        y+=panel_h+8
    jobs=vhc.get("jobs",[]); seen_j=set(); unique_jobs=[]
    for j in jobs:
        n=j.get("Name","")
        if n and n not in seen_j and n!="Totals": seen_j.add(n); unique_jobs.append(j)
    if unique_jobs:
        row_h=14; jbox_h=24+len(unique_jobs)*row_h+8
        parts+=[_box(ox+10,y,zw-20,jbox_h,"#1a6b3a"),_header_bar(ox+10,y,zw-20,12,"#1a6b3a"),
                _svgtext(ox+zw//2,y+9,f"Jobs  ({len(unique_jobs)})",10,"white","700","middle"),
                _svgtext(ox+18,y+22,"Job",9,"#888","700"),_svgtext(ox+190,y+22,"Repository",9,"#888","700"),
                _svgtext(ox+310,y+22,"Ret.",9,"#888","700"),_svgtext(ox+355,y+22,"GFS",9,"#888","700")]
        jy=y+28
        for j in unique_jobs[:14]:
            jn=_esc(j.get("Name",""))[:22]; jr=_esc(j.get("Repository",""))[:18]
            jgfs="✅" if j.get("GFS Enabled","") in ("✅","True","true") else ""
            jc="#1a6b3a" if "copy" in j.get("Job Type","").lower() else "#333"
            parts+=[_svgtext(ox+18,jy,jn,9,jc),_svgtext(ox+190,jy,jr,9,"#555"),
                    _svgtext(ox+310,jy,f"{j.get('Retention Scheme','')[:3]} {j.get('Restore Points','')}",9,"#555"),
                    _svgtext(ox+355,jy,jgfs,9,"#1a7a3c")]
            jy+=row_h
        if len(unique_jobs)>14: parts.append(_svgtext(ox+18,jy,f"… +{len(unique_jobs)-14} more jobs",9,"#888"))
        y+=jbox_h+8
    zone_h=y-oy+20
    return _zone(ox,oy,zw,zone_h,"#005b99","VEEAM BACKUP INFRASTRUCTURE","▣")+"\n"+"\n".join(str(p) for p in parts), zone_h

def _build_storage_zone(vhc, env, report):
    parts=[]; ox,oy=892,84; zw=454
    y=oy+32; repos=vhc.get("repositories",[]); extents=vhc.get("sobr_extents",[])
    blockers=report.get("analysis",{}).get("upgrade_blockers",[]); coverage=report.get("analysis",{}).get("coverage_gaps",[])
    for item,itype in [(r,"repo") for r in repos]+[(e,"extent") for e in extents]:
        rn=_esc(item.get("Name","")); rtype=item.get("Type",""); rc=_repo_color(rtype); rl=_repo_label(rtype)
        rfree=item.get("Free Space (TB)",""); rtotal=item.get("Total Space (TB)",""); rfreep=item.get("Free Space %","")
        rtasks=item.get("Set Tasks","") or item.get("Job Count",""); rimm=item.get("Use Immutability","")
        rimm_ok=rimm in ("✅","True","true"); rjobs=item.get("Job Count",""); rpvm=item.get("Per-VM","")
        try: f=float(str(rfree).replace(",","")); t=float(str(rtotal).replace(",","")); used_pct=round((t-f)/t*100) if t else 0
        except: used_pct=0
        item_h=136
        icon_map={"DDBoost":"💾","Linux":"🐧","Hardened":"🔒","Windows":"🪟","Object":"☁","SOBR":"📦"}
        icon=next((v for k,v in icon_map.items() if k.lower() in rl.lower()),"🗄️")
        parts+=[_box(ox+10,y,zw-20,item_h,rc),_header_bar(ox+10,y,zw-20,18,rc),
                f'<rect x="{ox+18}" y="{y+26}" width="36" height="36" rx="5" fill="{rc}"/>',
                _svgtext(ox+36,y+38,icon,16,anchor="middle"),_svgtext(ox+36,y+52,itype.upper()[:6],7,"white",anchor="middle"),
                _svgtext(ox+62,y+34,rn,13,"#1a1a3a","700"),
                _svg_badge(ox+62,y+40,rl,rc,w=max(60,len(rl)*6+14)),
                _svgtext(ox+62,y+62,f"Tasks: {rtasks}  ·  Per-VM: {_bool_icon(rpvm)}  ·  Immutable: {_bool_icon(rimm)}",9,"#555"),
                _svgtext(ox+62,y+78,f"Gateway: {_esc(item.get('Specified Gateway(s)','') or 'Auto/Direct')}  ·  Jobs: {rjobs}",9,"#555")]
        if rtotal:
            bw=zw-84; bx=ox+62; by=y+92; uw=max(2,round(bw*used_pct/100))
            parts+=[f'<rect x="{bx}" y="{by}" width="{bw}" height="10" rx="5" fill="#e8ecf0"/>',
                    f'<rect x="{bx}" y="{by}" width="{uw}" height="10" rx="5" fill="{rc}"/>',
                    _svgtext(bx,by+18,f"{rfree} TB free / {rtotal} TB total  ({rfreep})",9,"#555")]
        if not rimm_ok: parts.append(_svgtext(ox+zw-90,y+item_h-8,"⚠ No Immutability",9,"#c0392b","700"))
        y+=item_h+10
    recs=[]
    if not env.get("hardened_repos"): recs.append(("Deploy Linux Hardened Repo","No immutable copy — 3-2-1-1-0 gap. Add XFS repo with immutability."))
    if not env.get("has_backup_copy"): recs.append(("Create Backup Copy Jobs","No Backup Copy detected — offsite copy is missing."))
    if not env.get("has_surebackup"): recs.append(("Enable SureBackup","No recovery verification — add Virtual Lab + SureBackup job."))
    for b in blockers:
        if b.get("status")=="UNKNOWN": recs.append((f"Verify: {b.get('check','')}",b.get("detail","")[:80]))
    for c in coverage:
        if c.get("status")=="FAIL": recs.append((c.get("gap","Coverage gap"),c.get("action","")[:80]))
    if recs:
        rec_h=22+len(recs)*30
        parts+=[_box(ox+10,y,zw-20,rec_h,"#c05c00",fill="#fffbf0"),_header_bar(ox+10,y,zw-20,14,"#c05c00"),
                _svgtext(ox+zw//2,y+10,f"⚠  RECOMMENDATIONS  ({len(recs)})",10,"white","700","middle")]
        ry=y+20
        for title,detail in recs:
            parts+=[_svgtext(ox+18,ry+11,f"• {_esc(title)}",10,"#c05c00","700"),_svgtext(ox+18,ry+22,_esc(detail[:75]),9,"#555")]
            ry+=30
        y+=rec_h+8
    zone_h=y-oy+20
    return _zone(ox,oy,zw,zone_h,"#1a7a3c","STORAGE  LAYER","◉")+"\n"+"\n".join(str(p) for p in parts), zone_h

def _build_connectors(vhc):
    return ('\n'.join(['<line x1="442" y1="160" x2="468" y2="160" stroke="#888" stroke-width="1.5" stroke-dasharray="4,3" marker-end="url(#ag)"/>',
        _svgtext(452,155,"API",8,"#999",anchor="middle"),
        '<line x1="876" y1="340" x2="892" y2="340" stroke="#005b99" stroke-width="2" marker-end="url(#ab)"/>',
        '<line x1="442" y1="280" x2="468" y2="310" stroke="#005b99" stroke-width="2" marker-end="url(#ab)"/>',
        '<rect x="426" y="280" width="54" height="14" rx="3" fill="#e0eeff" stroke="#99bbdd" stroke-width="1"/>',
        _svgtext(453,290,"Src data",8,"#005b99",anchor="middle")]))

def _build_recommended_svg(vhc, env, report):
    """Build a recommended-architecture SVG showing what should be deployed."""
    parts=[]; ox,oy=14,84; zw=1332
    vm_count=env.get("vm_count",0); tier=env.get("tier","small")
    cur_proxies=env.get("proxy_count",0); rec_proxies=env.get("recommended_proxies",2)
    has_hardened=bool(env.get("hardened_repos")); has_sobr=env.get("has_sobr",False)
    has_object=bool(env.get("object_repos")); has_bc=env.get("has_backup_copy",True)
    has_sb=env.get("has_surebackup",True)
    add_proxies=max(0,rec_proxies-cur_proxies)
    bs=vhc.get("backup_server",{}); bsn=_esc(bs.get("name","VBR Server"))

    # ── header band ──────────────────────────────────────────────────────────
    parts+=[f'<rect x="0" y="{oy}" width="1360" height="24" rx="0" fill="#1a3a5c"/>',
            _svgtext(680,oy+15,"RECOMMENDED ARCHITECTURE  —  Veeam Best Practice (3-2-1-1-0 Rule)",12,"white","700","middle")]
    y=oy+34

    def _card(x,cy,w,h,title,color,badge=None,add=False,items=None):
        border=color if not add else "#27ae60"
        bg="#f0fff4" if add else "white"
        out=[_box(x,cy,w,h,border,fill=bg),_header_bar(x,cy,w,18,border)]
        if add:
            out+=[_svg_badge(x+w-72,cy+22,"➕ ADD","#27ae60",w=66)]
        if badge:
            out+=[_svg_badge(x+8,cy+22,badge,color)]
        out+=[_svgtext(x+8,cy+42,title,11,"#1a1a3a","700")]
        for i,(txt,clr) in enumerate(items or []):
            out+=[_svgtext(x+8,cy+58+i*16,txt,9,clr or "#555")]
        return out

    col_w=300; gap=18; cols_x=[14, 14+col_w+gap, 14+2*(col_w+gap), 14+3*(col_w+gap)]

    # ── Column 1: VBR Server ─────────────────────────────────────────────────
    cx=cols_x[0]
    parts+=_card(cx,y,col_w,90,bsn,"#005b99","BACKUP SERVER",add=False,
        items=[("Dedicated role — no proxy or repo",None),
               (f"Windows Server 2022  ·  Recommended: 8+ cores",None),
               ("Config DB: SQL Server 2016+ required for v13",None if not vhc.get("config_db",{}).get("version") else "#27ae60")])
    y2=y+100

    # Mount server (always recommend as separate)
    parts+=_card(cx,y2,col_w,74,"Mount / Utility Server","#555","WIN SERVER",add=True,
        items=[("Windows Server — File Level Restore (FLR)","#555"),
               ("Veeam Explorers staging (SQL, Exchange)","#555"),
               ("Recommended: 4 vCPU · 16 GB RAM · 200 GB disk","#888")])
    y2+=84

    # SureBackup
    if not has_sb:
        parts+=_card(cx,y2,col_w,60,"SureBackup / Virtual Lab","#6d9e3f","RECOVERY VERIFY",add=True,
            items=[("Automated backup verification","#555"),("Add Virtual Lab + SureBackup job","#888")])
        y2+=70

    # ── Column 2: Proxies ────────────────────────────────────────────────────
    cx=cols_x[1]
    proxy_h=70+max(cur_proxies,rec_proxies)*36
    parts+=[_box(cx,y,col_w,proxy_h,"#0077aa"),_header_bar(cx,y,col_w,10,"#0077aa"),
            _svgtext(cx+col_w//2,y+8,f"Backup Proxies  (target: {rec_proxies})",10,"white","700","middle")]
    py2=y+18
    for i in range(rec_proxies):
        existing=i<cur_proxies
        bg="#f0f7ff" if existing else "#f0fff4"
        bc="#0077aa" if existing else "#27ae60"
        lbl="EXISTING" if existing else "➕ ADD"
        lbl_c="#0077aa" if existing else "#27ae60"
        parts+=[_box(cx+6,py2,col_w-12,28,bc,fill=bg,shadow=False),
                _svgtext(cx+12,py2+11,f"{'VMware' if existing else 'Linux'} Proxy {i+1}",10,"#1a1a3a","700"),
                _svgtext(cx+12,py2+22,"4+ cores · 8+ GB RAM · HotAdd preferred" if not existing else "existing",8,"#555"),
                _svg_badge(cx+col_w-64,py2+6,lbl,lbl_c,w=58)]
        py2+=32

    # ── Column 3: Primary Storage ────────────────────────────────────────────
    cx=cols_x[2]; sy=y
    parts+=_card(cx,sy,col_w,80,"Linux Hardened Repository","#00695c","IMMUTABLE",add=not has_hardened,
        items=[("XFS filesystem · Immutability enabled","#555"),
               ("Physical server preferred (not VM)","#555"),
               ("SSH disabled · Dedicated service account","#555")])
    sy+=90

    # SOBR
    if tier in ("medium","large"):
        parts+=_card(cx,sy,col_w,70,"Scale-Out Backup Repository","#e65100","SOBR",add=not has_sobr,
            items=[("Wrap repos into SOBR for capacity tiering","#555"),
                   ("Enables capacity tier (cloud) offload","#555")])
        sy+=80

    # Existing DDBoost repos
    for r in [rp for rp in vhc.get("repositories",[]) if "ddboost" in rp.get("Type","").lower()][:2]:
        parts+=_card(cx,sy,col_w,60,_esc(r.get("Name","DDBoost")),"#1565c0","DDBOOST",add=False,
            items=[(f"{r.get('Total Space (TB)','?')} TB total  ·  {r.get('Free Space %','?')} free","#555")])
        sy+=70

    # ── Column 4: Offsite / Object ───────────────────────────────────────────
    cx=cols_x[3]; oy4=y
    parts+=_card(cx,oy4,col_w,80,"Object Storage (Offsite)","#0277bd","S3 / AZURE",add=not has_object,
        items=[("S3-compatible, Azure Blob, or Wasabi","#555"),
               ("Enable immutability (Object Lock)","#555"),
               ("Satisfies 3-2-1-1-0 offsite requirement","#555")])
    oy4+=90

    if not has_bc:
        parts+=_card(cx,oy4,col_w,70,"Backup Copy Job","#1a6b3a","COPY JOB",add=True,
            items=[("Schedule copy to offsite/object repo","#555"),
                   ("Use GFS (Weekly/Monthly/Yearly)","#555")])
        oy4+=80

    # Always show 3-2-1-1-0 rule summary
    parts+=_card(cx,oy4,col_w,100,"3-2-1-1-0 Rule","#333","TARGET STATE",add=False,
        items=[("✅  3 copies of data" if True else "",None),
               ("✅  2 different media types" if True else "",None),
               ("✅  1 offsite copy" if has_object else "⚠  1 offsite copy  — MISSING","#c0392b" if not has_object else "#27ae60"),
               ("✅  1 immutable copy" if has_hardened else "⚠  1 immutable copy — MISSING","#c0392b" if not has_hardened else "#27ae60"),
               ("✅  0 errors verified by SureBackup" if has_sb else "⚠  0 errors — SureBackup needed","#c0392b" if not has_sb else "#27ae60")])
    oy4+=110

    total_y=max(y2,py2+10,sy,oy4)+20
    zone_h=total_y-oy
    return (f'<svg viewBox="0 0 1360 {total_y}" xmlns="http://www.w3.org/2000/svg" width="100%">'
            +_SVG_DEFS+"\n".join(str(p) for p in parts)+"</svg>"), zone_h


def _build_gap_table(vhc, env, report):
    """Build an HTML gap analysis table comparing current vs recommended."""
    analysis=report.get("analysis",{})
    blockers=analysis.get("upgrade_blockers",[]); deprecated=analysis.get("deprecated_features",[])
    security=analysis.get("security_compliance",[]); coverage=analysis.get("coverage_gaps",[])
    s=report.get("summary",{})

    def badge(status):
        colors={"FAIL":"#c0392b","WARN":"#e67e22","PASS":"#27ae60","UNKNOWN":"#7f8c8d"}
        c=colors.get(status,"#aaa")
        return f'<span style="background:{c};color:white;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700">{status}</span>'

    rows=""
    # Upgrade blockers
    for b in blockers:
        st=b.get("status","UNKNOWN")
        rows+=f'<tr><td>Upgrade Blocker</td><td><b>{_esc(b.get("check",""))}</b></td><td>{badge(st)}</td><td style="font-size:11px">{_esc(b.get("detail","")[:120])}</td><td style="font-size:11px;color:#005b99">{_esc(b.get("action","") or "")[:100]}</td></tr>\n'
    # Deprecated features
    for d in deprecated:
        st=d.get("status","UNKNOWN")
        if st != "PASS":
            rows+=f'<tr><td>Deprecated Feature</td><td><b>{_esc(d.get("check",""))}</b></td><td>{badge(st)}</td><td style="font-size:11px">{_esc(d.get("detail","")[:120])}</td><td style="font-size:11px;color:#005b99">{_esc(d.get("action","") or "")[:100]}</td></tr>\n'
    # Security
    for sec in security:
        st=sec.get("status","UNKNOWN")
        if st == "FAIL":
            rows+=f'<tr><td>Security</td><td><b>{_esc(sec.get("check",""))}</b></td><td>{badge(st)}</td><td style="font-size:11px">{_esc(sec.get("detail","")[:120])}</td><td style="font-size:11px;color:#005b99">{_esc(sec.get("action","") or "")[:100]}</td></tr>\n'
    # Coverage gaps
    for c in coverage:
        st=c.get("status","WARN")
        rows+=f'<tr><td>Coverage Gap</td><td><b>{_esc(c.get("gap",""))}</b></td><td>{badge(st)}</td><td style="font-size:11px">{_esc(c.get("detail","")[:120])}</td><td style="font-size:11px;color:#005b99">{_esc(c.get("action","") or "")[:100]}</td></tr>\n'
    # Architecture gaps
    if not env.get("hardened_repos"):
        rows+=f'<tr><td>Architecture</td><td><b>No Immutable Repository</b></td><td>{badge("FAIL")}</td><td style="font-size:11px">No Linux hardened repo detected. 3-2-1-1-0 rule requires one immutable copy.</td><td style="font-size:11px;color:#005b99">Deploy Linux server with XFS, enable immutability in VBR, disable SSH.</td></tr>\n'
    if not env.get("has_backup_copy"):
        rows+=f'<tr><td>Architecture</td><td><b>No Backup Copy Job</b></td><td>{badge("FAIL")}</td><td style="font-size:11px">No offsite copy job configured — single point of failure.</td><td style="font-size:11px;color:#005b99">Create Backup Copy job to offsite or object storage repository with GFS retention.</td></tr>\n'
    if not env.get("has_surebackup"):
        rows+=f'<tr><td>Architecture</td><td><b>No Recovery Verification</b></td><td>{badge("WARN")}</td><td style="font-size:11px">No SureBackup jobs — backups are not verified for recoverability.</td><td style="font-size:11px;color:#005b99">Create Virtual Lab and SureBackup job to automate recovery verification.</td></tr>\n'
    if not env.get("object_repos"):
        rows+=f'<tr><td>Architecture</td><td><b>No Object Storage / Offsite Target</b></td><td>{badge("WARN")}</td><td style="font-size:11px">No cloud object storage repository configured for offsite copy.</td><td style="font-size:11px;color:#005b99">Add S3-compatible, Azure Blob, or Wasabi repository as offsite target.</td></tr>\n'
    rec_px=env.get("recommended_proxies",2); cur_px=env.get("proxy_count",0)
    if cur_px < rec_px:
        rows+=f'<tr><td>Architecture</td><td><b>Insufficient Proxy Count</b></td><td>{badge("WARN")}</td><td style="font-size:11px">Current: {cur_px} proxies for {env.get("vm_count",0)} VMs. Recommended: {rec_px} (1 per {_VMS_PER_PROXY} VMs).</td><td style="font-size:11px;color:#005b99">Deploy {rec_px-cur_px} additional Linux proxy server(s), 4+ cores, 8+ GB RAM each.</td></tr>\n'

    return f"""<div style="padding:16px">
<h2 style="font-size:16px;font-weight:700;color:#005b99;border-bottom:3px solid #005b99;padding-bottom:6px;margin-bottom:12px">
  Gap Analysis — Current vs Recommended &nbsp;
  <span style="font-size:12px;font-weight:400;color:#888">({s.get('FAIL',0)} FAILs · {s.get('WARN',0)} WARNs · {s.get('PASS',0)} PASSes)</span>
</h2>
<table style="width:100%;border-collapse:collapse;font-size:12px">
<thead><tr style="background:#005b99;color:white">
  <th style="padding:8px 10px;text-align:left;width:110px">Category</th>
  <th style="padding:8px 10px;text-align:left">Check</th>
  <th style="padding:8px 10px;text-align:center;width:80px">Status</th>
  <th style="padding:8px 10px;text-align:left">Detail</th>
  <th style="padding:8px 10px;text-align:left">Recommended Action</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
</div>"""


_DIAGRAM_HTML="""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Veeam Architecture — {site}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#e8edf2;font-family:'Segoe UI',Arial,sans-serif}}
.page-header{{background:#005b99;padding:14px 20px;border-bottom:4px solid #00b050;display:flex;align-items:center;gap:16px}}
.page-header h1{{font-size:18px;font-weight:700;color:white;letter-spacing:.3px}}
.page-header .sub{{font-size:11px;color:#a8d4f0;margin-top:2px}}
.tabs{{display:flex;background:#1a2535;padding:0 16px}}
.tab{{padding:10px 20px;color:#8aaccc;font-size:12px;font-weight:600;cursor:pointer;border-bottom:3px solid transparent;transition:all .15s}}
.tab:hover{{color:white}}
.tab.active{{color:white;border-bottom-color:#00b050;background:#243040}}
.tab-content{{display:none;background:white}}
.tab-content.active{{display:block}}
svg text{{font-family:'Segoe UI',Arial,sans-serif}}
.leg{{display:flex;flex-wrap:wrap;gap:14px;padding:8px 20px;background:#f8f9fb;border-top:1px solid #dde3ea;font-size:11px;color:#555}}
.li{{display:flex;align-items:center;gap:5px}}.sq{{width:12px;height:12px;border-radius:3px}}
table td,table th{{padding:6px 10px;border-bottom:1px solid #eee;vertical-align:top}}
table tbody tr:hover{{background:#f8faff}}
</style>
<script>
function showTab(id){{
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('content-'+id).classList.add('active');
  document.getElementById('tab-'+id).classList.add('active');
}}
</script>
</head>
<body>
<div class="page-header">
  <div>
    <h1>🏭 {site_title} — Veeam Architecture Report</h1>
    <div class="sub">VBR v{vbr_ver}  ·  {edition}  ·  {used}/{total_lic} licenses  ·  Scanned: {scan_date}</div>
  </div>
</div>
<div class="tabs">
  <div class="tab active" id="tab-current" onclick="showTab('current')">📐 Current Architecture</div>
  <div class="tab" id="tab-recommended" onclick="showTab('recommended')">✅ Recommended Architecture</div>
  <div class="tab" id="tab-gaps" onclick="showTab('gaps')">⚠️ Gap Analysis ({fail_count} FAILs · {warn_count} WARNs)</div>
</div>

<div id="content-current" class="tab-content active">
  <svg viewBox="0 0 1360 {total_h}" xmlns="http://www.w3.org/2000/svg" width="100%">
  {defs}{header}{vsphere}{veeam}{storage}{connectors}
  <rect x="14" y="{flowbar_y}" width="1332" height="16" rx="4" fill="#2a3a4a"/>
  <text x="680" y="{flowbar_ty}" fill="white" font-size="10" font-weight="700" text-anchor="middle">DATA FLOW:  Production VMs  →  Proxy  →  Primary Repo  →  Backup Copy  →  Offsite/DR</text>
  </svg>
  <div class="leg"><strong>Legend:</strong>
  <div class="li"><div class="sq" style="background:#4a6e8f"></div>vSphere Zone</div>
  <div class="li"><div class="sq" style="background:#005b99"></div>Veeam Infrastructure</div>
  <div class="li"><div class="sq" style="background:#00695c"></div>Hardened/Immutable Repo</div>
  <div class="li"><div class="sq" style="background:#1565c0"></div>DDBoost/Object Repo</div>
  <div class="li"><div class="sq" style="background:#0077aa"></div>Proxy</div>
  <div class="li" style="color:#c0392b">⚠ = issue requiring action</div>
  <div class="li"><div class="sq" style="background:#27ae60"></div>➕ ADD = recommended new component</div>
  </div>
</div>

<div id="content-recommended" class="tab-content">
  {recommended_svg}
  <div class="leg"><strong>Legend:</strong>
  <div class="li"><div class="sq" style="background:#005b99"></div>Existing component</div>
  <div class="li"><div class="sq" style="background:#27ae60"></div>➕ ADD — new component needed</div>
  <div class="li"><div class="sq" style="background:#e65100"></div>SOBR</div>
  <div class="li"><div class="sq" style="background:#0277bd"></div>Object / Offsite</div>
  <div class="li"><div class="sq" style="background:#00695c"></div>Hardened / Immutable</div>
  </div>
</div>

<div id="content-gaps" class="tab-content">
  {gap_table}
</div>

</body></html>"""


def generate_diagram_html(vhc, rvtools, report, output_path):
    env=_classify_env(vhc,rvtools); site=Path(report.get("meta",{}).get("vhc_file","vbr")).stem
    vs_svg,vs_h=_build_vsphere_zone(vhc,env,rvtools)
    vz_svg,vz_h=_build_veeam_zone(vhc,env,report)
    st_svg,st_h=_build_storage_zone(vhc,env,report)
    content_h=max(vs_h,vz_h,st_h); total_h=84+content_h+36
    flowbar_y=total_h-20; flowbar_ty=total_h-9
    rec_svg,_=_build_recommended_svg(vhc,env,report)
    gap_html=_build_gap_table(vhc,env,report)
    bs=vhc.get("backup_server",{}); lic=vhc.get("license",{}); s=report.get("summary",{})
    html=_DIAGRAM_HTML.format(
        site=_esc(site),
        site_title=_esc(site.upper()),
        vbr_ver=_esc(bs.get("version","")),
        edition=_esc(lic.get("Edition","") or ""),
        used=_esc(lic.get("Used Inst.","")),
        total_lic=_esc(lic.get("Licensed Inst.","")),
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        fail_count=s.get("FAIL",0),
        warn_count=s.get("WARN",0),
        total_h=total_h,flowbar_y=flowbar_y,flowbar_ty=flowbar_ty,
        defs=_SVG_DEFS,header=_build_svg_header(env,vhc,report),
        vsphere=vs_svg,veeam=vz_svg,storage=st_svg,
        connectors=_build_connectors(vhc),
        recommended_svg=rec_svg,
        gap_table=gap_html)
    Path(output_path).write_text(html,encoding="utf-8")
    log.info(f"Architecture diagram: {output_path}"); return output_path


# ═════════════════════════════════════════════════════════════════════════════
# HTML SITE REPORT  (card-based, from RVTools + optional VHC)
# ═════════════════════════════════════════════════════════════════════════════

_CSS="""
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#ecf0f1;color:#2c3e50;font-size:13px}
.page{max-width:1240px;margin:0 auto;padding:16px}
h1{font-size:22px;font-weight:700;color:white}
h2{font-size:15px;font-weight:700;color:#005b99;margin:20px 0 10px;border-bottom:2px solid #005b99;padding-bottom:4px}
h3{font-size:13px;font-weight:700;color:#34495e;margin-bottom:6px}
.header{background:#005b99;padding:16px 24px;border-bottom:4px solid #00b050;display:flex;align-items:center;gap:20px}
.header .logo{font-size:28px;font-weight:900;color:white;letter-spacing:-1px}
.header .meta{color:#a8d4f0;font-size:12px;margin-top:2px}
.kpi-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:16px 0}
.kpi{background:white;border-radius:8px;padding:14px 16px;box-shadow:0 1px 4px #0001;text-align:center}
.kpi .val{font-size:28px;font-weight:700;color:#005b99}.kpi .lbl{font-size:11px;color:#888;margin-top:2px}
.card{background:white;border-radius:8px;padding:16px;box-shadow:0 1px 4px #0001;margin-bottom:14px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#f4f7fb;color:#555;font-weight:600;text-align:left;padding:7px 10px;border-bottom:2px solid #dde3ea}
td{padding:6px 10px;border-bottom:1px solid #edf0f3;vertical-align:middle}
tr:last-child td{border-bottom:none}tr:hover td{background:#f8faff}
.bar-wrap{background:#e8ecf0;border-radius:4px;height:10px;min-width:100px;overflow:hidden}
.bar-fill{height:10px;border-radius:4px}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;color:white}
.badge-pass{background:#27ae60}.badge-warn{background:#e67e22}.badge-fail{background:#c0392b}.badge-unknown{background:#7f8c8d}
.finding{border-left:4px solid #ddd;margin:8px 0;padding:10px 14px;border-radius:0 6px 6px 0}
.finding.FAIL{border-color:#c0392b;background:#fdecea}.finding.WARN{border-color:#e67e22;background:#fef9e7}
.finding.PASS{border-color:#27ae60;background:#eafaf1}.finding.UNKNOWN{border-color:#95a5a6;background:#f5f6f7}
.finding .title{font-weight:700;font-size:12px}.finding .detail{font-size:11px;color:#555;margin-top:4px}
.finding .action{font-size:11px;color:#005b99;margin-top:4px}.finding .ref{font-size:10px;color:#95a5a6;margin-top:2px;font-style:italic}
.vendor-pill{display:inline-block;padding:2px 10px;border-radius:12px;font-size:10px;font-weight:600;background:#e8f4fd;color:#1a5276;border:1px solid #aed6f1;margin:1px}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.section-note{font-size:11px;color:#888;margin-bottom:8px}
.tag{display:inline-block;padding:1px 7px;border-radius:4px;font-size:10px;margin:1px;background:#f0f3f8;color:#555;border:1px solid #dde3ea}
.tag.eol{background:#fdecea;color:#c0392b;border-color:#f5b7b1}.tag.warn{background:#fef9e7;color:#a04000;border-color:#f9c98d}
.tag.ok{background:#eafaf1;color:#1e8449;border-color:#a9dfbf}
.footer{text-align:center;font-size:10px;color:#aaa;margin-top:20px;padding:10px}
@media(max-width:800px){.two-col{grid-template-columns:1fr}}
"""

_SEV_ORDER={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"NONE":4}

def _html_badge(status):
    cls={"PASS":"pass","WARN":"warn","FAIL":"fail","UNKNOWN":"unknown"}.get(status,"unknown")
    return f'<span class="badge badge-{cls}">{_esc(status)}</span>'

def _html_bar(pct,width=120):
    w=max(2,round(width*min(pct,100)/100))
    color="#c0392b" if pct>=DS_CRIT_PCT else ("#e67e22" if pct>=DS_WARN_PCT else "#27ae60")
    return (f'<div class="bar-wrap" style="width:{width}px">'
            f'<div class="bar-fill" style="width:{w}px;background:{color}"></div></div>')

def _site_inner_html(site_id, xlsx_name, html_name, rv, vhc_report, docs, gaps, tab_id, scan_time=None):
    if scan_time is None: scan_time=datetime.now().strftime("%Y-%m-%d %H:%M")
    if rv and not rv.get("error"):
        total_vms=len(rv["non_templates"]); powered_on=len(rv["powered_on"]); templates=len(rv["templates"])
        total_ds=len(rv["datastores"]); total_hosts=len(rv["hosts"]); snap_count=len(rv["snapshots"])
        total_cap=round(sum(d["cap_gib"] for d in rv["datastores"])/1024,1)
        total_free=round(sum(d["free_gib"] for d in rv["datastores"])/1024,1)
        vendor_summ=_vendor_summary(rv["datastores"])
    else:
        total_vms=powered_on=templates=total_ds=total_hosts=snap_count=0; total_cap=total_free=0.0; vendor_summ={}
    fail_count=sum(1 for g in gaps if g["status"]=="FAIL")
    warn_count=sum(1 for g in gaps if g["status"]=="WARN")
    pass_count=sum(1 for g in gaps if g["status"]=="PASS")
    doc_links=" · ".join(f'<a href="{v["url"]}" target="_blank" style="color:#a8d4f0">{k}</a>' for k,v in docs.items() if v.get("status")=="fetched")
    parts=[f"""<div id="{_esc(tab_id)}" class="tab-content" style="display:none">
<div class="site-header">
  <div class="site-title">{_esc(site_id.upper())}</div>
  <div class="site-meta">RVTools: {_esc(xlsx_name)} &nbsp;·&nbsp; VHC: {_esc(html_name)} &nbsp;·&nbsp; {doc_links}</div>
  <div style="display:flex;gap:8px;margin-top:8px;">
    <div class="kpi-badge fail">{fail_count} FAIL</div>
    <div class="kpi-badge warn">{warn_count} WARN</div>
    <div class="kpi-badge pass">{pass_count} PASS</div>
  </div>
</div><div class="page">"""]
    parts.append('<div class="kpi-row">')
    for val,lbl in [(str(total_vms),"Total VMs"),(str(powered_on),"Powered On"),(str(templates),"Templates"),
                    (str(total_hosts),"ESXi Hosts"),(f"{total_cap:.1f}","Capacity (TiB)"),(f"{total_free:.1f}","Free Space (TiB)"),
                    (str(total_ds),"Datastores"),(str(snap_count),"Active Snapshots")]:
        parts.append(f'<div class="kpi"><div class="val">{_esc(val)}</div><div class="lbl">{_esc(lbl)}</div></div>')
    parts.append("</div>")
    if rv and not rv.get("error"):
        parts.append('<h2>VM Inventory</h2><div class="two-col">')
        parts.append('<div class="card"><h3>Guest OS Distribution</h3><table><tr><th>OS</th><th>VMs</th><th>%</th></tr>')
        for os_name,cnt in list(_os_breakdown(rv["non_templates"]).items())[:20]:
            is_eol=any(p.lower() in os_name.lower() for p in ["eol","2008","2012","2003","xp","vista"])
            pct_val=round(cnt/max(total_vms,1)*100,1)
            rc=' style="color:#c0392b"' if is_eol else ""
            parts.append(f'<tr><td{rc}>{_esc(os_name)}</td><td>{cnt}</td><td>{pct_val}%</td></tr>')
        parts.append("</table></div>")
        parts.append('<div class="card"><h3>Clusters</h3><table><tr><th>Cluster</th><th>VMs</th><th>On</th><th>Hosts</th><th>Cores</th><th>RAM (GiB)</th></tr>')
        for c in _cluster_summary(rv["non_templates"],rv["hosts"])[:15]:
            parts.append(f'<tr><td>{_esc(c["name"])}</td><td>{c["vms"]}</td><td>{c["powered_on"]}</td><td>{c["host_count"]}</td><td>{c["host_cores"]}</td><td>{c["host_mem_gib"]:.0f}</td></tr>')
        parts.append("</table></div></div>")
        esxi_bd=_esxi_breakdown(rv["hosts"])
        if esxi_bd:
            parts.append('<div class="card"><h3>ESXi Host Versions</h3><div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:6px;">')
            for ver,cnt in sorted(esxi_bd.items(),reverse=True):
                major=ver.split(".")[0] if ver else "?"
                st_lbl,_c=ESXI_STATUS.get(major,("unknown","#888"))
                cls="ok" if st_lbl=="current" else ("warn" if st_lbl=="supported" else "eol")
                parts.append(f'<span class="tag {cls}">ESXi {_esc(ver)} — {cnt} host(s) [{st_lbl}]</span>')
            parts.append("</div></div>")
        if rv["datastores"]:
            parts.append('<h2>Storage</h2>')
            if vendor_summ:
                parts.append('<div class="card"><h3>Storage Vendors Detected</h3><div style="margin-top:6px;">')
                for vendor,vstats in sorted(vendor_summ.items(),key=lambda x:-x[1]["cap_gib"]):
                    parts.append(f'<span class="vendor-pill">{_esc(vendor)} — {vstats["count"]} DS | {vstats["cap_gib"]:.1f} GiB total | {vstats["free_gib"]:.1f} GiB free</span>')
                parts.append("</div></div>")
            parts.append('<div class="card"><h3>Datastores</h3>')
            parts.append('<p class="section-note">Veeam BP (bp.veeam.com/vbr): maintain ≥25% free space on datastores hosting backed-up VMs</p>')
            parts.append('<table><tr><th>Datastore</th><th>Type</th><th>Vendor</th><th>Capacity (GiB)</th><th>Free (GiB)</th><th>Used %</th><th>Utilisation</th><th>VMs</th><th>Status</th></tr>')
            for ds in sorted(rv["datastores"],key=lambda d:-d["used_pct"]):
                st="FAIL" if ds["used_pct"]>=DS_CRIT_PCT else ("WARN" if ds["used_pct"]>=DS_WARN_PCT else "PASS")
                parts.append(f'<tr><td title="{_esc(ds["name"])}">{_esc(ds["name"][:38])}</td><td>{_esc(ds["type"])}</td>'
                    f'<td><span class="vendor-pill">{_esc(ds["vendor"])}</span></td>'
                    f'<td style="text-align:right">{ds["cap_gib"]:.1f}</td><td style="text-align:right">{ds["free_gib"]:.1f}</td>'
                    f'<td style="text-align:right">{ds["used_pct"]:.1f}%</td><td>{_html_bar(ds["used_pct"])}</td>'
                    f'<td style="text-align:right">{_esc(str(ds["num_vms"]))}</td><td>{_html_badge(st)}</td></tr>')
            parts.append("</table></div>")
    parts.append('<h2>Best Practice Analysis</h2>')
    parts.append('<p class="section-note">Sources: bp.veeam.com/vbr · helpcenter.veeam.com/docs/vbr/userguide/?ver=13 · veeam.com/knowledge-base.html</p>')
    for g in sorted(gaps,key=lambda g:(_SEV_ORDER.get(g.get("severity","NONE"),4),g.get("status",""))):
        st=g.get("status","UNKNOWN")
        parts.append(f'<div class="finding {st}"><div class="title">{_html_badge(st)} {_esc(g["check"])}</div>')
        if g.get("detail"): parts.append(f'<div class="detail">{_esc(g["detail"])}</div>')
        if g.get("action"): parts.append(f'<div class="action">→ {_esc(g["action"])}</div>')
        if g.get("ref"): parts.append(f'<div class="ref">📖 {_esc(g["ref"])}</div>')
        parts.append("</div>")
    if vhc_report:
        parts.append('<h2>VHC Analysis (Veeam Health Check)</h2>')
        for section_name,findings in vhc_report.get("analysis",{}).items():
            fail_f=[f for f in findings if f.get("status") in ("FAIL","WARN","UNKNOWN")]
            if not fail_f: continue
            parts.append(f'<div class="card"><h3>{_esc(section_name.replace("_"," ").title())}</h3>')
            for f in fail_f:
                st=f.get("status","UNKNOWN"); check=f.get("check") or f.get("rule") or f.get("gap") or f.get("component") or "?"
                parts.append(f'<div class="finding {st}" style="margin:6px 0"><div class="title">{_html_badge(st)} {_esc(str(check))}</div>')
                if f.get("evidence"): parts.append(f'<div class="detail">{_esc(str(f["evidence"]))}</div>')
                if f.get("action"): parts.append(f'<div class="action">→ {_esc(str(f["action"]))}</div>')
                parts.append("</div>")
            parts.append("</div>")
    if rv and rv.get("snapshots"):
        parts.append('<h2>Active Snapshots</h2><div class="card"><table><tr><th>VM</th><th>Snapshot Name</th><th>Created</th><th>Size (GiB)</th></tr>')
        for s in sorted(rv["snapshots"],key=lambda x:-x.get("size_gib",0))[:30]:
            parts.append(f'<tr><td>{_esc(s["vm"])}</td><td>{_esc(s["name"])}</td><td>{_esc(s["created"])}</td><td>{s["size_gib"]:.1f}</td></tr>')
        parts.append("</table></div>")
    parts.append(f'<div class="footer">bp.veeam.com/vbr · helpcenter.veeam.com · veeam.com/knowledge-base.html</div>')
    parts.append("</div></div>")
    return "\n".join(parts)

def _diagram_svg_block(vhc_data, rv, report):
    """Return an inline SVG block for embedding (no full HTML wrapper)."""
    env=_classify_env(vhc_data, rv)
    vs_svg,vs_h=_build_vsphere_zone(vhc_data,env,rv)
    vz_svg,vz_h=_build_veeam_zone(vhc_data,env,report)
    st_svg,st_h=_build_storage_zone(vhc_data,env,report)
    content_h=max(vs_h,vz_h,st_h); total_h=84+content_h+36
    flowbar_y=total_h-20; flowbar_ty=total_h-9
    return (f'<svg viewBox="0 0 1360 {total_h}" xmlns="http://www.w3.org/2000/svg" '
            f'style="width:100%;max-width:1360px;display:block;margin:0 auto">'
            +_SVG_DEFS
            +_build_svg_header(env,vhc_data,report)
            +vs_svg+vz_svg+st_svg
            +_build_connectors(vhc_data)
            +f'<rect x="14" y="{flowbar_y}" width="1332" height="16" rx="4" fill="#2a3a4a"/>'
            +f'<text x="680" y="{flowbar_ty}" fill="white" font-size="10" font-weight="700" text-anchor="middle">'
            +'DATA FLOW:  Production VMs  →  Proxy  →  Primary Repo  →  Backup Copy  →  Offsite/DR</text>'
            +'</svg>')

def build_combined_html(site_results, site_tabs, scan_time):
    """Build one self-contained HTML file — sidebar nav + all site content embedded as tabs."""
    total_vms=sum(s["kpis"].get("vms",0) for s in site_results)
    total_powered=sum(s["kpis"].get("powered_on",0) for s in site_results)
    total_cap=round(sum(s["kpis"].get("cap_tib",0.0) for s in site_results),1)
    total_fails=sum(s["fails"] for s in site_results)
    total_warns=sum(s["warns"] for s in site_results)

    # Sidebar nav entries
    nav_html=""
    for s in sorted(site_results,key=lambda x:x["site_id"]):
        dot="#c0392b" if s["fails"] else ("#e67e22" if s["warns"] else "#27ae60")
        src="📊" if "RVTools" in s["sources"] else ""
        src+="📋" if "VHC" in s["sources"] else ""
        has_d=s.get("has_diagram",False)
        diag_link=(f'<span class="nav-diag" onclick="event.stopPropagation();showTab(\'{_esc(s["site_id"])}-diag\')">⬡</span>' if has_d else "")
        nav_html+=(f'<div class="nav-item" onclick="showTab(\'{_esc(s["site_id"])}\')" id="nav-{_esc(s["site_id"])}">'
                   f'<span class="dot" style="background:{dot}"></span>'
                   f'<span class="nav-label">{_esc(s["site_id"].upper())}</span>'
                   f'<span class="nav-src">{src}</span>{diag_link}</div>\n')

    # Fleet summary table
    fleet_rows=""
    for s in sorted(site_results,key=lambda x:(-x["fails"],-x["warns"],x["site_id"])):
        k=s["kpis"]; vendors=", ".join(s.get("vendors",[])[:3])
        bg="background:#fdecea" if s["fails"] else ("background:#fef9e7" if s["warns"] else "")
        fc=f'{_html_badge("FAIL")} {s["fails"]}' if s["fails"] else "—"
        wc=f'{_html_badge("WARN")} {s["warns"]}' if s["warns"] else "—"
        diag_btn=(f' <button class="diag-btn" onclick="showTab(\'{_esc(s["site_id"])}-diag\')">diagram</button>' if s.get("has_diagram") else "")
        fleet_rows+=(f'<tr style="{bg}"><td><button class="site-link" onclick="showTab(\'{_esc(s["site_id"])}\')">{_esc(s["site_id"].upper())}</button></td>'
            f'<td>{k.get("vms",0)}</td><td>{k.get("powered_on",0)}</td><td>{k.get("hosts",0)}</td>'
            f'<td>{k.get("datastores",0)}</td><td>{k.get("cap_tib",0):.1f}</td><td>{k.get("free_tib",0):.1f}</td>'
            f'<td>{k.get("snapshots",0)}</td><td style="font-size:10px">{_esc(vendors)}</td>'
            f'<td>{fc}</td><td>{wc}</td><td style="font-size:10px">{_esc(s.get("sources",""))}{diag_btn}</td></tr>\n')

    # Vendor fleet summary
    all_vendors: dict={}
    for s in site_results:
        for vendor,vstats in s.get("vendor_detail",{}).items():
            if vendor not in all_vendors: all_vendors[vendor]={"sites":0,"count":0,"cap_gib":0.0}
            all_vendors[vendor]["sites"]+=1; all_vendors[vendor]["count"]+=vstats["count"]; all_vendors[vendor]["cap_gib"]+=vstats["cap_gib"]
    vendor_cards="".join(
        f'<div class="vendor-card"><div class="vc-name">{_esc(v)}</div>'
        f'<div class="vc-stat">{vstats["sites"]} site(s) · {vstats["count"]} DS</div>'
        f'<div class="vc-cap">{round(vstats["cap_gib"]/1024,1):.1f} TiB</div></div>'
        for v,vstats in sorted(all_vendors.items(),key=lambda x:-x[1]["cap_gib"]))

    fleet_tab=(f'<div id="tab-summary" class="tab-content" style="display:block">'
        f'<div class="site-header"><div class="site-title">Fleet Summary — All Sites</div>'
        f'<div class="site-meta">{scan_time} · {len(site_results)} sites · Veeam v13 Readiness</div>'
        f'<div style="display:flex;gap:8px;margin-top:8px;">'
        f'<div class="kpi-badge" style="background:#1a5276">{total_vms} VMs</div>'
        f'<div class="kpi-badge" style="background:#1a5276">{total_powered} On</div>'
        f'<div class="kpi-badge" style="background:#1a5276">{total_cap:.1f} TiB</div>'
        f'<div class="kpi-badge fail">{total_fails} FAILs</div>'
        f'<div class="kpi-badge warn">{total_warns} WARNs</div></div></div>'
        f'<div class="page"><h2>All Sites</h2>'
        f'<p class="section-note">Click a site name to open its full report · Click column headers to sort</p>'
        f'<div class="card"><table id="fleetTbl" class="sortable">'
        f'<tr><th onclick="sortTbl(0)">Site</th><th onclick="sortTbl(1)">VMs</th><th onclick="sortTbl(2)">On</th>'
        f'<th onclick="sortTbl(3)">Hosts</th><th onclick="sortTbl(4)">DS</th>'
        f'<th onclick="sortTbl(5)">Cap (TiB)</th><th onclick="sortTbl(6)">Free (TiB)</th>'
        f'<th onclick="sortTbl(7)">Snaps</th><th onclick="sortTbl(8)">Vendors</th>'
        f'<th onclick="sortTbl(9)">FAIL</th><th onclick="sortTbl(10)">WARN</th><th>Sources</th></tr>'
        f'{fleet_rows}</table></div>'
        f'<h2>Storage Vendors — Fleet View</h2>'
        f'<div class="card"><div class="vendor-grid">{vendor_cards}</div></div>'
        f'</div></div>')

    all_tab_content=fleet_tab+"\n".join(site_tabs)

    css_extra="""
html,body{height:100%;overflow:hidden}
body{display:flex;flex-direction:column}
.topbar{background:#005b99;color:white;padding:10px 18px;border-bottom:4px solid #00b050;
  display:flex;align-items:center;gap:16px;flex-shrink:0}
.topbar .logo{font-size:22px;font-weight:900;letter-spacing:-1px}
.topbar .topright{margin-left:auto;display:flex;gap:8px;align-items:center}
.main-layout{display:flex;flex:1;overflow:hidden}
.sidebar{width:192px;min-width:192px;background:#1a2535;overflow-y:auto;flex-shrink:0;padding:6px 0}
.sidebar-lbl{font-size:9px;font-weight:700;color:#4a6080;padding:8px 12px 3px;letter-spacing:1px;text-transform:uppercase}
.nav-item{display:flex;align-items:center;gap:6px;padding:6px 10px;cursor:pointer;color:#c8d8e8;
  font-size:11px;border-left:3px solid transparent;transition:background .1s}
.nav-item:hover{background:#243040;color:white}
.nav-item.active{background:#243040;border-left-color:#00b050;color:white;font-weight:600}
.nav-fleet{color:#7ec8e3;font-weight:700;font-size:12px;border-bottom:1px solid #2a3a50;margin-bottom:4px}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.nav-label{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nav-src{font-size:9px;opacity:.5}
.nav-diag{font-size:10px;color:#7ec8e3;cursor:pointer;padding:0 2px}
.nav-diag:hover{color:white}
.content-area{flex:1;overflow-y:auto;background:#ecf0f1}
.tab-content{display:none}
.site-header{background:#005b99;color:white;padding:12px 20px;border-bottom:4px solid #00b050}
.site-title{font-size:18px;font-weight:700}
.site-meta{font-size:11px;color:#a8d4f0;margin-top:2px}
.kpi-badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;color:white;background:#555}
.kpi-badge.fail{background:#c0392b}.kpi-badge.warn{background:#e67e22}.kpi-badge.pass{background:#27ae60}
.diagram-wrap{background:#e8edf2;padding:12px;overflow-x:auto}
.sortable th{cursor:pointer;user-select:none}.sortable th:hover{background:#dde8f5}
.site-link{background:none;border:none;color:#005b99;cursor:pointer;font-weight:700;font-size:12px;padding:0;text-decoration:underline}
.diag-btn{background:#005b99;color:white;border:none;border-radius:4px;padding:2px 7px;font-size:10px;cursor:pointer;margin-left:4px}
.vendor-grid{display:flex;flex-wrap:wrap;gap:10px}
.vendor-card{background:#f4f7fb;border:1px solid #dde3ea;border-radius:8px;padding:10px 14px;min-width:150px}
.vc-name{font-weight:700;color:#005b99;font-size:12px}.vc-stat{font-size:11px;color:#888;margin-top:2px}.vc-cap{font-size:12px;color:#2c3e50}
"""

    js="""
function showTab(id){
  document.querySelectorAll('.tab-content').forEach(t=>t.style.display='none');
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  var el=document.getElementById(id);
  if(el){el.style.display='block'; el.scrollTop=0;}
  var nav=document.getElementById('nav-'+id);
  if(nav) nav.classList.add('active');
}
function sortTbl(n){
  var t=document.getElementById('fleetTbl'),rows,x,y,i,sw=true,dir='asc',swc=0;
  while(sw){sw=false;rows=t.rows;
    for(i=1;i<rows.length-1;i++){
      x=rows[i].cells[n].innerText.toLowerCase();y=rows[i+1].cells[n].innerText.toLowerCase();
      var xn=parseFloat(x),yn=parseFloat(y);if(!isNaN(xn)&&!isNaN(yn)){x=xn;y=yn;}
      if((dir=='asc'&&x>y)||(dir=='desc'&&x<y)){rows[i].parentNode.insertBefore(rows[i+1],rows[i]);sw=true;swc++;}
    }if(swc==0&&dir=='asc'){dir='desc';sw=true;swc=0;}}
}
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Veeam Fleet Analyzer — {_esc(scan_time)}</title>
<style>{_CSS}{css_extra}</style>
<script>{js}</script>
</head>
<body>
<div class="topbar">
  <div class="logo">Veeam</div>
  <div style="font-size:14px;font-weight:700">Fleet Architecture Analyzer</div>
  <div style="font-size:11px;color:#a8d4f0">{scan_time} · {len(site_results)} sites</div>
  <div class="topright">
    <span class="kpi-badge" style="background:#1a5276">{total_vms} VMs</span>
    <span class="kpi-badge" style="background:#1a5276">{total_cap:.1f} TiB</span>
    <span class="kpi-badge fail">{total_fails} FAILs</span>
    <span class="kpi-badge warn">{total_warns} WARNs</span>
  </div>
</div>
<div class="main-layout">
<div class="sidebar">
  <div class="nav-item nav-fleet" onclick="showTab('tab-summary')" id="nav-tab-summary">
    📊 &nbsp;Fleet Summary</div>
  <div class="sidebar-lbl">Sites</div>
  {nav_html}
</div>
<div class="content-area">
{all_tab_content}
</div>
</div>
</body>
</html>"""


# ═════════════════════════════════════════════════════════════════════════════
# JSON REPORT BUILDER
# ═════════════════════════════════════════════════════════════════════════════

def build_report(vhc_path, vhc, docs, doc_keywords, rvtools=None):
    blockers=analyze_upgrade_blockers(vhc); deprecated=analyze_deprecated_features(vhc)
    security=analyze_security_compliance(vhc); os_compat=analyze_os_compatibility(vhc)
    coverage=analyze_coverage_gaps(vhc); workloads=analyze_workload_incompatibilities(vhc)
    rvtools_findings=analyze_rvtools(vhc,rvtools) if rvtools else []
    all_findings=blockers+deprecated+security+os_compat+coverage+workloads+rvtools_findings
    def cs(findings,status): return sum(1 for f in findings if f.get("status")==status)
    summary={"total_checks":len(all_findings),"PASS":cs(all_findings,STATUS_PASS),
        "FAIL":cs(all_findings,STATUS_FAIL),"WARN":cs(all_findings,STATUS_WARN),"UNKNOWN":cs(all_findings,STATUS_UNKNOWN)}
    fails=summary["FAIL"]; unknowns=summary["UNKNOWN"]
    if fails>5 or any(b["status"]==STATUS_FAIL for b in blockers):
        readiness="NOT_READY — Hard blockers or critical failures must be resolved before upgrade."
    elif fails>0 or unknowns>2:
        readiness="CONDITIONAL — Address all FAILs and resolve UNKNOWNs before scheduling upgrade."
    else:
        readiness="READY — No hard blockers detected. Proceed with upgrade planning."
    return {"meta":{"scan_date":datetime.now().isoformat(),"vhc_file":str(Path(vhc_path).name),
        "veeam_version_installed":vhc.get("backup_server",{}).get("version",""),
        "veeam_version_target":"13.0.2.29","backup_server":vhc.get("backup_server",{}).get("name",""),
        "config_db_server":vhc.get("config_db",{}).get("server",""),
        "config_db_version":vhc.get("config_db",{}).get("version",""),
        "docs_fetched":{k:v["status"] for k,v in docs.items()}},
        "upgrade_readiness":readiness,"summary":summary,
        "analysis":{"upgrade_blockers":blockers,"deprecated_features":deprecated,"security_compliance":security,
            "os_compatibility":os_compat,"coverage_gaps":coverage,"workload_incompatibilities":workloads,"rvtools":rvtools_findings},
        "rvtools_inventory":{"vm_count":len(rvtools.get("non_templates",[])) if rvtools else 0,
            "datastore_count":len(rvtools.get("datastores",[])) if rvtools else 0,
            "powered_on_vms":len(rvtools.get("powered_on",[])) if rvtools else 0,
            "templates":len(rvtools.get("templates",[])) if rvtools else 0} if rvtools else None,
        "veeam_docs":{k:{"url":v["url"],"status":v["status"],"length":v.get("length",0)} for k,v in docs.items()},
        "doc_keywords_detected":doc_keywords}


# ═════════════════════════════════════════════════════════════════════════════
# BATCH DISCOVERY & SITE MATCHING
# ═════════════════════════════════════════════════════════════════════════════

def discover_files(scan_dir):
    xlsx=sorted(Path(scan_dir).glob("*.xlsx")); html=sorted(Path(scan_dir).glob("*.html"))
    log.info(f"Discovered: {len(xlsx)} xlsx, {len(html)} html in {scan_dir}"); return xlsx,html

def _site_prefix(path):
    stem=Path(path).stem.lower()
    stem=re.sub(r"(prdveeam|prdvcen|prdvcent|prdv|veeam|vcen|vcenter|\d+).*$","",stem)
    return stem.strip("-_. ")

def match_sites(xlsx_files, html_files):
    html_by_prefix={}
    for h in html_files:
        pfx=_site_prefix(h)
        if pfx: html_by_prefix.setdefault(pfx,h)
    sites=[]; matched_html=set()
    for xlsx in xlsx_files:
        pfx=_site_prefix(xlsx); matched=html_by_prefix.get(pfx)
        sites.append({"site_id":pfx or xlsx.stem,"xlsx":xlsx,"html":matched})
        if matched: matched_html.add(matched)
    for h in html_files:
        if h not in matched_html:
            pfx=_site_prefix(h); sites.append({"site_id":pfx or h.stem,"xlsx":None,"html":h})
    sites.sort(key=lambda s:s["site_id"])
    log.info(f"Sites: {len(sites)} total ({sum(1 for s in sites if s['xlsx'] and s['html'])} full, "
             f"{sum(1 for s in sites if s['xlsx'] and not s['html'])} xlsx-only, "
             f"{sum(1 for s in sites if not s['xlsx'])} vhc-only)"); return sites


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def _run_batch(args):
    scan_dir=Path(args.scan_dir); output_dir=Path(args.output_dir)
    output_dir.mkdir(parents=True,exist_ok=True)
    log.info(f"Scan dir:   {scan_dir}"); log.info(f"Output dir: {output_dir}")
    if args.no_fetch:
        docs={k:{"url":v,"status":"skipped","text":""} for k,v in VEEAM_DOC_URLS.items()}
    else:
        log.info("Fetching Veeam documentation…"); docs=fetch_veeam_docs()
    xlsx_files,html_files=discover_files(scan_dir); sites=match_sites(xlsx_files,html_files)
    scan_time=datetime.now().strftime("%Y-%m-%d %H:%M")
    site_results=[]; site_tabs=[]

    for site in sites:
        site_id=site["site_id"]
        log.info(f"\n{'='*60}\nProcessing site: {site_id.upper()}")
        rv=None
        if site["xlsx"]:
            rv=parse_rvtools(str(site["xlsx"]))
            if rv.get("error"): log.warning(f"  RVTools error: {rv['error']}"); rv=None
        vhc_report=None; vhc_data=None
        if site["html"]:
            try:
                vhc_data=parse_vhc(str(site["html"]))
                _docs_stub={k:{"url":v,"status":"skipped","text":""} for k,v in VEEAM_DOC_URLS.items()}
                vhc_report=build_report(str(site["html"]),vhc_data,_docs_stub,{},rvtools=rv)
            except Exception as e: log.warning(f"  VHC parse failed: {e}")
        gaps=_bp_gaps(rv,docs) if rv else []
        vhc_fails=vhc_report["summary"]["FAIL"] if vhc_report else 0
        vhc_warns=vhc_report["summary"]["WARN"] if vhc_report else 0
        fail_count=sum(1 for g in gaps if g["status"]=="FAIL")+vhc_fails
        warn_count=sum(1 for g in gaps if g["status"]=="WARN")+vhc_warns
        xlsx_name=site["xlsx"].name if site["xlsx"] else "—"
        html_name=site["html"].name if site["html"] else "—"

        # Build site report tab
        site_inner=_site_inner_html(site_id,xlsx_name,html_name,rv,vhc_report,docs,gaps,site_id,scan_time)
        site_tabs.append(site_inner)

        # Build inline SVG architecture diagram tab (VHC sites only)
        has_diagram=False
        if vhc_data and vhc_report:
            try:
                diag_tab_id=f"{site_id}-diag"
                svg_block=_diagram_svg_block(vhc_data,rv or {},vhc_report)
                site_tabs.append(
                    f'<div id="{_esc(diag_tab_id)}" class="tab-content" style="display:none">'
                    f'<div class="site-header"><div class="site-title">{_esc(site_id.upper())} — Architecture Diagram</div>'
                    f'<div class="site-meta">{_esc(html_name)}</div></div>'
                    f'<div class="diagram-wrap">{svg_block}</div>'
                    f'<div style="padding:8px 16px;background:#e8edf2;border-top:1px solid #dde3ea;">'
                    f'<div class="leg" style="background:transparent;border:none;padding:0">'
                    f'<strong>Legend:</strong>'
                    f'<span style="margin-left:8px;font-size:11px">⬡ vSphere</span>'
                    f'<span style="margin-left:8px;font-size:11px">▣ Veeam Infrastructure</span>'
                    f'<span style="margin-left:8px;font-size:11px">◉ Storage</span>'
                    f'<span style="margin-left:8px;font-size:11px;color:#c0392b">⚠ issue requiring action</span>'
                    f'</div></div></div>')
                has_diagram=True
                log.info(f"  Diagram tab: {diag_tab_id}")
            except Exception as e: log.warning(f"  Diagram skipped: {e}")

        kpis={"vms":len(rv["non_templates"]) if rv else 0,"powered_on":len(rv["powered_on"]) if rv else 0,
              "templates":len(rv["templates"]) if rv else 0,"hosts":len(rv["hosts"]) if rv else 0,
              "datastores":len(rv["datastores"]) if rv else 0,
              "cap_tib":round(sum(d["cap_gib"] for d in rv["datastores"])/1024,2) if rv else 0.0,
              "free_tib":round(sum(d["free_gib"] for d in rv["datastores"])/1024,2) if rv else 0.0,
              "snapshots":len(rv["snapshots"]) if rv else 0}
        # Save JSON per site (still useful for programmatic use)
        (output_dir/f"{site_id}_analysis.json").write_text(
            json.dumps({"site_id":site_id,"scan_date":datetime.now().isoformat(),
                "sources":{"xlsx":str(site["xlsx"]) if site["xlsx"] else None,"html":str(site["html"]) if site["html"] else None},
                "kpis":kpis,"bp_gaps":gaps,"vhc_summary":vhc_report["summary"] if vhc_report else None},
                indent=2,default=str),encoding="utf-8")
        vendors=list(_vendor_summary(rv["datastores"]).keys()) if rv else []
        sources=[]
        if site["xlsx"]: sources.append("RVTools")
        if site["html"]: sources.append("VHC")
        site_results.append({"site_id":site_id,"has_diagram":has_diagram,
            "fails":fail_count,"warns":warn_count,"kpis":kpis,"vendors":vendors,
            "vendor_detail":_vendor_summary(rv["datastores"]) if rv else {},"sources":" + ".join(sources)})
        log.info(f"  Processed: {site_id}")

    # Write single combined HTML file
    combined_html=build_combined_html(site_results,site_tabs,scan_time)
    out_path=output_dir/"veeam_fleet_report.html"
    out_path.write_text(combined_html,encoding="utf-8")
    log.info(f"\nCombined report: {out_path}")
    print(f"\n{'='*65}")
    print(f"  Veeam Analyzer — Batch Complete")
    print(f"  Sites: {len(site_results)}   Output: {out_path}")
    print(f"{'='*65}")
    for s in sorted(site_results,key=lambda x:(-x["fails"],-x["warns"])):
        icon="❌" if s["fails"] else ("⚠️ " if s["warns"] else "✅")
        print(f"  {icon}  {s['site_id'].upper():25s}  VMs:{s['kpis']['vms']:4d}  DS:{s['kpis']['datastores']:3d}  FAIL:{s['fails']}  WARN:{s['warns']}  [{s['sources']}]")
    print(f"{'='*65}")
    print(f"  Report: {out_path}")
    fsize=round(out_path.stat().st_size/1024/1024,1)
    print(f"  Size:   {fsize} MB")
    print(f"{'='*65}\n")

def _run_single(args):
    vhc_path=Path(args.vhc_html)
    if not vhc_path.exists(): log.error(f"VHC file not found: {vhc_path}"); sys.exit(1)
    vhc_data=parse_vhc(str(vhc_path))
    rv=None
    if args.rvtools:
        rv_path=Path(args.rvtools)
        if not rv_path.exists(): log.error(f"RVTools file not found: {rv_path}"); sys.exit(1)
        rv=parse_rvtools(str(rv_path))
        if rv.get("error"): log.warning(f"RVTools parse error: {rv['error']}"); rv=None
    if args.no_fetch:
        docs={k:{"url":v,"status":"skipped","text":""} for k,v in VEEAM_DOC_URLS.items()}
    else:
        docs=fetch_veeam_docs()
    doc_keywords=extract_doc_keywords(docs)
    report=build_report(str(vhc_path),vhc_data,docs,doc_keywords,rvtools=rv)
    out_path=Path(args.output)
    out_path.write_text(json.dumps(report,indent=2,default=str),encoding="utf-8")
    log.info(f"JSON report: {out_path}")
    gaps=_bp_gaps(rv,docs) if rv else []
    site_id=vhc_path.stem
    site_inner=_site_inner_html(site_id,Path(args.rvtools).name if args.rvtools else "—",vhc_path.name,rv,report,docs,gaps,site_id)
    # Wrap inner content in a complete standalone HTML page with full CSS
    site_html=f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Veeam Site Report — {site_id}</title>
<style>{_CSS}
.tab-content{{display:block !important}}
</style>
</head>
<body>
{site_inner}
</body>
</html>"""
    site_report_path=out_path.with_name(f"{site_id}_report.html")
    site_report_path.write_text(site_html,encoding="utf-8")
    log.info(f"Site report: {site_report_path}")
    if args.diagram_out:
        diag_path=args.diagram_out
    else:
        diag_path=str(out_path.with_suffix(""))+"_architecture.html"
    generate_diagram_html(vhc_data,rv or {},report,diag_path)
    bs=vhc_data.get("backup_server",{}); s=report["summary"]
    print(f"\n{'='*65}")
    print(f"  VHC ANALYZER — {vhc_path.name}")
    print(f"  VBR: {bs.get('name')} v{bs.get('version')}   Target: v13.0.2.29")
    print(f"  Readiness: {report['upgrade_readiness']}")
    print(f"  Checks: {s['total_checks']}  ✅{s['PASS']} PASS  ❌{s['FAIL']} FAIL  ⚠️{s['WARN']} WARN  ❓{s['UNKNOWN']} UNKNOWN")
    print(f"  JSON:    {out_path}")
    print(f"  Report:  {site_report_path}")
    print(f"  Diagram: {diag_path}")
    print(f"{'='*65}\n")
    sys.exit(1 if report["summary"]["FAIL"]>0 else 0)

def main():
    ap=argparse.ArgumentParser(description="Veeam Analyzer — single-file or batch mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  Single site:   python3 veeam_analyzer.py site.html --rvtools rvtools.xlsx
  Batch mode:    python3 veeam_analyzer.py --batch
  Custom dirs:   python3 veeam_analyzer.py --batch --scan-dir /path/to/files --output-dir /path/to/output
  No web fetch:  python3 veeam_analyzer.py --batch --no-fetch""")
    ap.add_argument("vhc_html",nargs="?",help="Path to VHC HTML file (single-site mode)")
    ap.add_argument("--rvtools","-r",default=None,help="RVTools Excel export (.xlsx)")
    ap.add_argument("--output","-o",default="vhc_analysis.json",help="JSON output path (default: vhc_analysis.json)")
    ap.add_argument("--diagram-out","-d",default=None,help="SVG architecture diagram output path")
    ap.add_argument("--batch",action="store_true",help="Batch mode: scan folder for all xlsx+html files")
    ap.add_argument("--scan-dir",default=str(DEFAULT_SCAN_DIR),help=f"Batch: folder to scan (default: {DEFAULT_SCAN_DIR})")
    ap.add_argument("--output-dir",default=str(DEFAULT_OUTPUT_DIR),help=f"Batch: output folder (default: {DEFAULT_OUTPUT_DIR})")
    ap.add_argument("--no-fetch",action="store_true",help="Skip live Veeam doc fetching")
    ap.add_argument("--version",type=int,default=13,help="Target Veeam version (default: 13)")
    args=ap.parse_args()
    if args.batch or not args.vhc_html:
        _run_batch(args)
    else:
        _run_single(args)

if __name__=="__main__":
    main()
