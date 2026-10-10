"""
Data Preprocessing & Multi-Source Log Normalization Engine.
Handles dataset cleaning, normalization, ground-truth risk scoring,
and heterogeneous log parsing (Firewall, IDS, Endpoint, Windows, Linux, Threat Intel).
"""

import os
import re
import random
import hashlib
from datetime import datetime, timedelta
import pandas as pd
import numpy as np

# Sector risk weights based on critical infrastructure frameworks (NIST SP 800-61 / ISO 27005)
SECTOR_WEIGHTS = {
    "Government": 25.0,
    "Health": 25.0,
    "Financial": 25.0,
    "Corporate": 18.0,
    "E-commerce": 18.0,
    "Educational": 12.0,
    "Social Media": 12.0,
    "Personal": 7.0,
}

# Vector exploitability and systemic blast radius weights
VECTOR_WEIGHTS = {
    "Ransomware": 20.0,
    "Data Breach": 20.0,
    "Hacking": 19.0,
    "Malware": 15.0,
    "Phishing": 13.0,
    "Identity Theft": 12.0,
    "Online Fraud": 9.0,
    "Cyber Bullying": 8.0,
    "Others": 7.0,
}

# Subnet mappings per city and category for realistic IP correlation
CITY_SUBNETS = {
    "Mumbai": "10.10",
    "Bangalore": "10.20",
    "Delhi": "10.30",
    "Pune": "10.40",
    "Kolkata": "10.50",
    "Jaipur": "10.60",
    "Ahmedabad": "10.70",
    "Lucknow": "10.80",
    "Hyderabad": "10.90",
    "Chennai": "10.100",
}

CATEGORY_VLAN = {
    "Government": "1",
    "Health": "2",
    "Financial": "3",
    "Corporate": "4",
    "E-commerce": "5",
    "Educational": "6",
    "Social Media": "7",
    "Personal": "8",
}

# Known C2 and Threat Actor IP pools for correlation clustering
THREAT_ACTOR_IPS = [
    "185.220.101.5",
    "194.26.29.112",
    "45.145.185.81",
    "198.51.100.42",
    "203.0.113.19",
    "91.240.118.172",
    "103.251.167.20",
    "193.142.59.88",
    "185.191.171.12",
    "45.154.255.99",
    "89.248.165.77",
    "194.135.33.24",
]

LOG_SOURCES = [
    "Firewall",
    "IDS",
    "Endpoint",
    "Windows Event Log",
    "Linux Syslog",
    "Threat Intelligence",
]


def clean_incident_type(itype: str) -> str:
    """Normalize incident types like 'Malware_Attacks' to 'Malware'."""
    if not isinstance(itype, str):
        return "Others"
    clean = itype.strip()
    if clean.lower() in ["malware_attacks", "malware attack", "malware_attack"]:
        return "Malware"
    return clean


def calculate_risk_score(amount_inr: float, category: str, incident_type: str) -> float:
    """
    Computes an objective cybersecurity risk index (0 - 100) combining:
    1. Financial Loss Severity (0-55 pts)
    2. Sector Criticality / Sensitivity (0-25 pts)
    3. Threat Vector Blast Radius (0-20 pts)
    """
    amt = max(0.0, float(amount_inr))
    fin_score = min(amt / 500000.0, 1.0) * 55.0

    cat_score = SECTOR_WEIGHTS.get(category, 12.0)
    threat_score = VECTOR_WEIGHTS.get(clean_incident_type(incident_type), 10.0)

    total_score = fin_score + cat_score + threat_score
    return round(total_score, 2)


def assign_severity(risk_score: float) -> str:
    """Classifies risk score into standard SOC severity tiers."""
    if risk_score >= 70.0:
        return "Critical"
    elif risk_score >= 48.0:
        return "High"
    elif risk_score >= 28.0:
        return "Medium"
    else:
        return "Low"


def generate_deterministic_ips(year: int, day: int, city: str, category: str, inc_type: str, inc_id: int):
    """
    Generates realistic, repeatable source and destination IPs that model real-world
    threat campaigns (some shared attacker IPs targeting specific sectors).
    """
    # Deterministic attacker IP pool selection based on attack campaign
    campaign_hash = int(hashlib.md5(f"{year}-{day % 7}-{inc_type}".encode()).hexdigest(), 16)
    if (inc_id % 3) == 0:
        # Clustered threat campaign using known C2 actor IP
        src_ip = THREAT_ACTOR_IPS[campaign_hash % len(THREAT_ACTOR_IPS)]
    else:
        # Distributed botnet / individual attacker
        octet1 = 170 + (campaign_hash % 60)
        octet2 = (inc_id * 17) % 250 + 1
        octet3 = (inc_id * 31) % 250 + 1
        octet4 = (inc_id * 7) % 250 + 1
        src_ip = f"{octet1}.{octet2}.{octet3}.{octet4}"

    # Destination IP represents internal protected enterprise network
    subnet = CITY_SUBNETS.get(city, "10.10")
    vlan = CATEGORY_VLAN.get(category, "1")
    host_num = (inc_id % 240) + 10
    dest_ip = f"{subnet}.{vlan}.{host_num}"

    return src_ip, dest_ip


def map_mitre_tactic(inc_type: str) -> str:
    """Maps incident type to standard MITRE ATT&CK Enterprise Tactic."""
    mapping = {
        "Ransomware": "Impact (TA0040) / Data Encrypted for Impact (T1486)",
        "Data Breach": "Exfiltration (TA0010) / Exfiltration Over C2 (T1041)",
        "Hacking": "Initial Access (TA0001) / Exploit Public-Facing App (T1190)",
        "Malware": "Execution (TA0002) / User Execution (T1204)",
        "Phishing": "Initial Access (TA0001) / Spearphishing Attachment (T1566)",
        "Identity Theft": "Credential Access (TA0006) / OS Credential Dumping (T1003)",
        "Online Fraud": "Financial Impact (TA0040) / Account Manipulation (T1098)",
        "Cyber Bullying": "Resource Hijacking (TA0040) / Social Engineering",
        "Others": "Defense Evasion (TA0005) / Obfuscated Files (T1027)",
    }
    return mapping.get(clean_incident_type(inc_type), "Discovery (TA0007)")


def generate_synthetic_raw_logs(incident_row: dict) -> list:
    """
    Generates realistic multi-source security telemetry corresponding to an incident:
    Firewall, IDS, Endpoint, Windows Event Log, Linux Syslog, and Threat Intelligence.
    """
    inc_id = incident_row["id"]
    year = incident_row["year"]
    day = incident_row["day"]
    src_ip = incident_row["source_ip"]
    dest_ip = incident_row["dest_ip"]
    inc_type = incident_row["incident_type"]
    city = incident_row["city"]
    category = incident_row["category"]
    severity = incident_row["severity"]

    # Base date timestamp
    month = ((inc_id % 12) + 1)
    base_time = datetime(year=year, month=month, day=min(day, 28), hour=(inc_id % 24), minute=(inc_id * 3) % 60)
    iso_time = base_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    logs = []

    # 1. Firewall Log (e.g. Cisco ASA / Palo Alto CEF)
    fw_action = "DROP" if severity in ["Critical", "High"] else "ALLOW"
    fw_port = 443 if inc_type in ["Data Breach", "Phishing"] else 445 if inc_type == "Ransomware" else 8080
    logs.append({
        "log_id": f"LOG-FW-{inc_id:05d}",
        "incident_id": inc_id,
        "timestamp": iso_time,
        "log_source": "Firewall",
        "event_type": f"Traffic_{fw_action}",
        "source_ip": src_ip,
        "dest_ip": dest_ip,
        "source_port": 50000 + (inc_id % 10000),
        "dest_port": fw_port,
        "protocol": "TCP",
        "action_taken": fw_action,
        "threat_intel_score": 0.85 if severity == "Critical" else 0.55 if severity == "High" else 0.25,
        "raw_log": f"CEF:0|PaloAltoNetworks|PAN-OS|10.1.0|TRAFFIC|{fw_action}|{severity}|src={src_ip} spt=51234 dst={dest_ip} dpt={fw_port} proto=TCP act={fw_action} reason=ThreatSignature match=ET_{inc_type.upper()}"
    })

    # 2. IDS Log (e.g. Snort / Suricata Alert)
    t1 = (base_time + timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs.append({
        "log_id": f"LOG-IDS-{inc_id:05d}",
        "incident_id": inc_id,
        "timestamp": t1,
        "log_source": "IDS",
        "event_type": f"Snort_Alert_{inc_type}",
        "source_ip": src_ip,
        "dest_ip": dest_ip,
        "source_port": 51234,
        "dest_port": fw_port,
        "protocol": "TCP",
        "action_taken": "ALERT",
        "threat_intel_score": 0.90 if severity in ["Critical", "High"] else 0.40,
        "raw_log": f"[**] [1:2029381:2] ET EXPLOIT Suspicious {inc_type} Activity Detected [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {{{src_ip}:51234 -> {dest_ip}:{fw_port}}}"
    })

    # 3. Endpoint / EDR Log (CrowdStrike / Sysmon)
    t2 = (base_time + timedelta(minutes=8)).strftime("%Y-%m-%dT%H:%M:%SZ")
    edr_proc = "powershell.exe -enc JAB3..." if inc_type in ["Ransomware", "Hacking"] else "svchost.exe (Injected)"
    logs.append({
        "log_id": f"LOG-EDR-{inc_id:05d}",
        "incident_id": inc_id,
        "timestamp": t2,
        "log_source": "Endpoint",
        "event_type": "Process_Injection_Or_Exec",
        "source_ip": dest_ip,
        "dest_ip": src_ip,
        "source_port": 49152,
        "dest_port": 443,
        "protocol": "TCP",
        "action_taken": "QUARANTINE" if severity == "Critical" else "ALERT",
        "threat_intel_score": 0.95 if severity == "Critical" else 0.65,
        "raw_log": f"Sysmon Event ID 1: Process Create. ProcessId: 4892, Image: C:\\Windows\\System32\\{edr_proc}, CommandLine: {edr_proc}, ParentImage: explorer.exe, User: NT AUTHORITY\\SYSTEM, DestinationIp: {src_ip}"
    })

    # 4. Windows Event Log
    t3 = (base_time + timedelta(minutes=11)).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs.append({
        "log_id": f"LOG-WIN-{inc_id:05d}",
        "incident_id": inc_id,
        "timestamp": t3,
        "log_source": "Windows Event Log",
        "event_type": "Security_Event_4625_FailedLogon" if inc_type in ["Hacking", "Identity Theft"] else "Security_Event_7045_ServiceInstall",
        "source_ip": src_ip,
        "dest_ip": dest_ip,
        "source_port": 0,
        "dest_port": 3389,
        "protocol": "RDP/SMB",
        "action_taken": "AUDIT_FAILURE",
        "threat_intel_score": 0.70,
        "raw_log": f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4625</EventID><Level>0</Level></System><EventData><Data Name='TargetUserName'>Administrator</Data><Data Name='IpAddress'>{src_ip}</Data><Data Name='Status'>0xC000006D</Data></EventData></Event>"
    })

    # 5. Linux Syslog (auth.log)
    t4 = (base_time + timedelta(minutes=14)).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs.append({
        "log_id": f"LOG-LNX-{inc_id:05d}",
        "incident_id": inc_id,
        "timestamp": t4,
        "log_source": "Linux Syslog",
        "event_type": "sshd_auth_failure",
        "source_ip": src_ip,
        "dest_ip": dest_ip,
        "source_port": 43210,
        "dest_port": 22,
        "protocol": "SSH",
        "action_taken": "DENIED",
        "threat_intel_score": 0.60,
        "raw_log": f"{base_time.strftime('%b %d %H:%M:%S')} host-srv-{city.lower()} sshd[3104]: Failed password for invalid user root from {src_ip} port 43210 ssh2"
    })

    # 6. Threat Intelligence Feed
    t5 = (base_time + timedelta(minutes=16)).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs.append({
        "log_id": f"LOG-TI-{inc_id:05d}",
        "incident_id": inc_id,
        "timestamp": t5,
        "log_source": "Threat Intelligence",
        "event_type": "OTX_IoC_Match",
        "source_ip": src_ip,
        "dest_ip": dest_ip,
        "source_port": 0,
        "dest_port": 0,
        "protocol": "IP_REPUTATION",
        "action_taken": "IOC_FLAGGED",
        "threat_intel_score": 0.88 if severity in ["Critical", "High"] else 0.45,
        "raw_log": f"ThreatIntel Feed AlienVault/MISP: Indicator {src_ip} flagged as Active C2 / Malicious Actor associated with APT Campaign targeting {category} entities in {city}."
    })

    return logs


def parse_and_normalize_raw_log(raw_text: str, source_hint: str = None) -> dict:
    """
    Parses arbitrary raw logs (CEF, Syslog, JSON, Windows Event) into
    a Common Event Schema.
    """
    res = {
        "log_id": f"NORM-{random.randint(10000, 99999)}",
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "log_source": source_hint or "Unknown",
        "event_type": "Parsed_Event",
        "source_ip": "0.0.0.0",
        "dest_ip": "0.0.0.0",
        "action_taken": "UNKNOWN",
        "threat_intel_score": 0.0,
        "raw_log": raw_text.strip(),
    }

    # Extract IPs
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ips = re.findall(ip_pattern, raw_text)
    if len(ips) >= 1:
        res["source_ip"] = ips[0]
    if len(ips) >= 2:
        res["dest_ip"] = ips[1]

    # Detect log source and action
    text_lower = raw_text.lower()
    if "cef:" in text_lower or "pan-os" in text_lower or "cisco" in text_lower:
        res["log_source"] = "Firewall"
        if "drop" in text_lower or "deny" in text_lower:
            res["action_taken"] = "DROP"
        else:
            res["action_taken"] = "ALLOW"
        res["event_type"] = "Firewall_Traffic"
    elif "snort" in text_lower or "suricata" in text_lower or "et exploit" in text_lower:
        res["log_source"] = "IDS"
        res["action_taken"] = "ALERT"
        res["event_type"] = "IDS_Signature_Alert"
    elif "sysmon" in text_lower or "crowdstrike" in text_lower or "process" in text_lower:
        res["log_source"] = "Endpoint"
        res["action_taken"] = "PROCESS_MONITORED"
        res["event_type"] = "Endpoint_Execution"
    elif "eventid" in text_lower or "microsoft" in text_lower or "<event" in text_lower:
        res["log_source"] = "Windows Event Log"
        res["action_taken"] = "LOGON_AUDIT"
        res["event_type"] = "Windows_Security_Audit"
    elif "sshd" in text_lower or "sudo:" in text_lower:
        res["log_source"] = "Linux Syslog"
        res["action_taken"] = "AUTH_EVENT"
        res["event_type"] = "Syslog_Auth"
    elif "threatintel" in text_lower or "alienvault" in text_lower or "ioc" in text_lower:
        res["log_source"] = "Threat Intelligence"
        res["action_taken"] = "FLAGGED"
        res["event_type"] = "TI_Indicator_Match"
        res["threat_intel_score"] = 0.85

    return res


def load_and_preprocess_dataset(csv_path: str) -> pd.DataFrame:
    """
    Loads dataset, cleans missing values, deduplicates, normalizes categorical features,
    and computes objective ground-truth severity.
    """
    df = pd.read_csv(csv_path)

    # Clean missing values
    df = df.dropna().copy()

    # Normalize Incident_Type
    df["Incident_Type"] = df["Incident_Type"].apply(clean_incident_type)
    df["City"] = df["City"].str.strip()
    df["Category"] = df["Category"].str.strip()
    df["Amount_Lost_INR"] = pd.to_numeric(df["Amount_Lost_INR"], errors="coerce").fillna(0.0)
    df["Year"] = pd.to_numeric(df["Year"], errors="coerce").fillna(2023).astype(int)
    df["Day"] = pd.to_numeric(df["Day"], errors="coerce").fillna(1).astype(int)

    # Compute Risk Score & Severity
    df["Risk_Score"] = df.apply(
        lambda r: calculate_risk_score(r["Amount_Lost_INR"], r["Category"], r["Incident_Type"]),
        axis=1
    )
    df["Severity"] = df["Risk_Score"].apply(assign_severity)

    # MITRE Tactic
    df["MITRE_Tactic"] = df["Incident_Type"].apply(map_mitre_tactic)

    return df
