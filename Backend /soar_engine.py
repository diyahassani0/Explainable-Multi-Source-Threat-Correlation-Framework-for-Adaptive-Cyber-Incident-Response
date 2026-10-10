"""
Adaptive Incident Response (SOAR) Engine.
Recommends context-aware containment actions (IP block, endpoint isolation,
credential revocation, incident escalation) and executes them in a safe
Simulated Response Mode with required analyst confirmation and rollback logs.
"""

from datetime import datetime
import json
import random

PLAYBOOKS = [
    {
        "playbook_id": "PB-101",
        "name": "Ransomware Containment & Endpoint Isolation",
        "description": "Quarantines compromised host network adapter, terminates malicious process trees, and preserves volatile RAM.",
        "target_type": "Endpoint / Host",
        "supported_vectors": ["Ransomware", "Malware"],
        "default_action": "Isolate Endpoint",
        "blast_radius": "Medium",
        "cli_command": "crowdstrike-cli host isolate --ip {dest_ip} --preserve-ram true",
        "rollback_command": "crowdstrike-cli host unisolate --ip {dest_ip}",
    },
    {
        "playbook_id": "PB-102",
        "name": "Border Firewall IP Blacklist & Rate Limit",
        "description": "Injects drop rules at enterprise border firewall and edge proxies for malicious C2 IPs.",
        "target_type": "Network / Firewall",
        "supported_vectors": ["Hacking", "Ransomware", "Data Breach", "Phishing"],
        "default_action": "Block Suspicious IP",
        "blast_radius": "Low",
        "cli_command": "paloalto-api add-rule --name 'BLOCK_{source_ip}' --source {source_ip} --action drop",
        "rollback_command": "paloalto-api remove-rule --name 'BLOCK_{source_ip}'",
    },
    {
        "playbook_id": "PB-103",
        "name": "Compromised Identity Session Revocation",
        "description": "Revokes Active Directory Kerberos tickets, invalidates active OAuth tokens, and forces MFA re-auth.",
        "target_type": "Identity / IAM",
        "supported_vectors": ["Identity Theft", "Online Fraud", "Phishing"],
        "default_action": "Revoke User Credentials",
        "blast_radius": "Low",
        "cli_command": "azuread-cli user revoke-sessions --target-upn analyst@{category.lower()}.local",
        "rollback_command": "azuread-cli user restore-sessions --target-upn analyst@{category.lower()}.local",
    },
    {
        "playbook_id": "PB-104",
        "name": "Data Exfiltration Sever & DLP Invalidation",
        "description": "Severs outbound TLS sockets to external storage buckets and invokes Data Protection Officer (DPO) protocol.",
        "target_type": "DLP / Proxy Gateway",
        "supported_vectors": ["Data Breach"],
        "default_action": "Sever Data Exfiltration Channel",
        "blast_radius": "High",
        "cli_command": "dlp-guard kill-session --dest {source_ip} --quarantine-bucket /corp/vault",
        "rollback_command": "dlp-guard unblock-session --dest {source_ip}",
    },
    {
        "playbook_id": "PB-105",
        "name": "Critical Incident Escalation & War-Room Setup",
        "description": "Paginates Tier-3 CSIRT commanders, creates Slack/Teams war room, and locks forensic evidence.",
        "target_type": "SOC Management",
        "supported_vectors": ["All Critical Incidents", "Cyber Bullying", "Others"],
        "default_action": "Escalate Incident to Tier-3",
        "blast_radius": "None",
        "cli_command": "pagerduty-api trigger --service CSIRT_TIER3 --incident-id {incident_id} --urgency high",
        "rollback_command": "pagerduty-api resolve --incident-id {incident_id}",
    },
]


def recommend_response_action(incident: dict) -> dict:
    """
    Evaluates incident parameters and recommends the optimal adaptive response playbook.
    """
    inc_type = incident.get("incident_type", "Others")
    severity = incident.get("severity", "Medium")
    src_ip = incident.get("source_ip", "198.51.100.42")
    dest_ip = incident.get("dest_ip", "10.10.1.15")
    category = incident.get("category", "Corporate")
    inc_id = incident.get("id", 1)

    selected_pb = None
    for pb in PLAYBOOKS:
        if inc_type in pb["supported_vectors"]:
            selected_pb = pb
            break

    if selected_pb is None:
        selected_pb = PLAYBOOKS[1] if severity in ["Critical", "High"] else PLAYBOOKS[4]

    # Format actual command with incident parameters
    cmd = selected_pb["cli_command"].format(
        source_ip=src_ip,
        dest_ip=dest_ip,
        category=category,
        incident_id=inc_id,
    )
    rollback = selected_pb["rollback_command"].format(
        source_ip=src_ip,
        dest_ip=dest_ip,
        category=category,
        incident_id=inc_id,
    )

    rationale = (
        f"Incident #{inc_id} involves '{inc_type}' with assessed severity '{severity}'. "
        f"Target entity belongs to '{category}'. Recommended playbook '{selected_pb['name']}' "
        f"mitigates active adversary dwell time by applying '{selected_pb['default_action']}'."
    )

    return {
        "playbook_id": selected_pb["playbook_id"],
        "playbook_name": selected_pb["name"],
        "recommended_action": selected_pb["default_action"],
        "target_entity": dest_ip if "Endpoint" in selected_pb["default_action"] else src_ip,
        "blast_radius": selected_pb["blast_radius"],
        "rationale": rationale,
        "command_template": cmd,
        "rollback_template": rollback,
        "simulation_mode": True,  # Safe simulated execution by default
    }


def execute_simulated_action(payload: dict) -> dict:
    """
    Simulates adaptive security action execution with safety safeguards.
    Requires explicit analyst confirmation.
    """
    inc_id = payload.get("incident_id")
    action_type = payload.get("action_type", "Block IP")
    target_entity = payload.get("target_entity", "198.51.100.42")
    playbook_id = payload.get("playbook_id", "PB-102")
    confirmed = payload.get("confirmed", False)
    analyst_id = payload.get("analyst_id", "SOC_Analyst_Lead")
    simulated = payload.get("simulated", True)

    if not confirmed:
        return {
            "success": False,
            "status": "Awaiting Confirmation",
            "message": "Security action rejected: Explicit analyst confirmation is required prior to execution.",
        }

    now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    latency_ms = random.randint(45, 180)

    # Simulated CLI execution stdout
    stdout = (
        f"[{now_iso}] [SOAR-ORCHESTRATOR] Initializing Playbook {playbook_id}...\n"
        f"[{now_iso}] [SANDBOX] Safety dry-run validation passed. Blast radius risk: Low.\n"
        f"[{now_iso}] [ACTION-EXEC] Applying {action_type} on target entity '{target_entity}'...\n"
        f"[{now_iso}] [REMOTE-GATEWAY] API response 200 OK. State transitioned to ENFORCED.\n"
        f"[{now_iso}] [AUDIT] Logged execution under analyst '{analyst_id}'. Latency: {latency_ms}ms.\n"
        f"[{now_iso}] [STATUS] Action successfully applied in SIMULATED mode. Real network unchanged."
    )

    action_record = {
        "incident_id": inc_id,
        "action_type": action_type,
        "target_entity": target_entity,
        "playbook_name": playbook_id,
        "execution_mode": "Simulated" if simulated else "Active (Enforced)",
        "status": "Executed (Simulated)",
        "blast_radius_risk": "Low",
        "analyst_id": analyst_id,
        "executed_at": now_iso,
        "details": stdout,
    }

    return {
        "success": True,
        "status": "Executed (Simulated)",
        "action_id": random.randint(1000, 9999),
        "execution_record": action_record,
        "message": f"Successfully simulated '{action_type}' on '{target_entity}'. System state updated.",
        "stdout": stdout,
    }
