import json
import uuid
from datetime import datetime
from typing import Dict, Any, List

class SOARPlaybooks:
    """
    Security Orchestration, Automation, and Response (SOAR) Engine.
    Executes automated defense playbooks for high-confidence threats:
    - Message Quarantine & User Notification
    - Firewall / DNS Sinkhole Rule Generation (RPZ, iptables, Cisco)
    - STIX 2.1 Threat Intelligence Bundle Export (OASIS Standard)
    - SIEM Incident Log Export (Splunk CIM & Elasticsearch ECS)
    """

    @staticmethod
    def quarantine_message(scan_data: Dict[str, Any], analyst: str = "Automated AI Playbook") -> Dict[str, Any]:
        """Simulate enterprise mailbox quarantine and revocation."""
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        return {
            "status": "QUARANTINED",
            "incident_id": incident_id,
            "timestamp": timestamp,
            "executed_by": analyst,
            "action": "Message isolated from recipient inboxes across tenant",
            "sender_email": scan_data.get("sender_email"),
            "subject": scan_data.get("subject"),
            "risk_score": scan_data.get("risk_score"),
            "quarantine_mailbox": "quarantine-vault@enterprise-defense.internal",
            "audit_trail": {
                "hash": scan_data.get("evidence_hash"),
                "status": "LOCKED_PENDING_ANALYST_REVIEW"
            }
        }

    @staticmethod
    def generate_firewall_rules(scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate network defense rules for Firewall and DNS Sinkholes."""
        origin_ip = scan_data.get("origin_ip") or "0.0.0.0"
        domain = scan_data.get("sender_domain") or "malicious-unknown.com"
        
        # Linux iptables rule
        iptables_rule = f"iptables -A INPUT -s {origin_ip} -j DROP -m comment --comment 'PhishTrace-AutoBlock-Threat-{domain}'"
        
        # BIND DNS Sinkhole (Response Policy Zone - RPZ)
        rpz_rule = f"{domain} CNAME .\n*.{domain} CNAME ."
        
        # Cisco ASA ACL rule
        cisco_rule = f"access-list OUTSIDE_BLOCK extended deny ip host {origin_ip} any"
        
        # Windows PowerShell Firewall rule
        ps_rule = f"New-NetFirewallRule -DisplayName 'Block PhishTrace Malicious IP {origin_ip}' -Direction Inbound -Action Block -RemoteAddress {origin_ip}"

        return {
            "target_domain": domain,
            "target_ip": origin_ip,
            "iptables": iptables_rule,
            "dns_rpz_sinkhole": rpz_rule,
            "cisco_acl": cisco_rule,
            "powershell_firewall": ps_rule,
            "recommendation": f"Add {domain} to corporate egress proxy blocklist and sinkhole DNS queries."
        }

    @staticmethod
    def generate_stix_bundle(scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate an OASIS STIX 2.1 JSON Threat Intelligence Bundle.
        The global standard for sharing cyber threat indicators (IOCs).
        """
        bundle_id = f"bundle--{uuid.uuid4()}"
        indicator_id = f"indicator--{uuid.uuid4()}"
        observed_data_id = f"observed-data--{uuid.uuid4()}"
        identity_id = f"identity--{uuid.uuid4()}"
        
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        domain = scan_data.get("sender_domain") or "unknown-domain.com"
        ip = scan_data.get("origin_ip") or "127.0.0.1"

        stix_bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": [
                {
                    "type": "identity",
                    "spec_version": "2.1",
                    "id": identity_id,
                    "created": timestamp,
                    "modified": timestamp,
                    "name": "PhishTrace AI Security Center",
                    "identity_class": "system"
                },
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": timestamp,
                    "modified": timestamp,
                    "name": f"Phishing Infrastructure: {domain}",
                    "description": f"Email phishing threat originating from IP {ip} spoofing {domain}. Risk score {scan_data.get('risk_score', 0)}/100.",
                    "indicator_types": ["malicious-activity", "phishing"],
                    "pattern": f"[domain-name:value = '{domain}'] OR [ipv4-addr:value = '{ip}']",
                    "pattern_type": "stix",
                    "valid_from": timestamp,
                    "confidence": int(scan_data.get("risk_score", 75))
                },
                {
                    "type": "observed-data",
                    "spec_version": "2.1",
                    "id": observed_data_id,
                    "created": timestamp,
                    "modified": timestamp,
                    "first_observed": timestamp,
                    "last_observed": timestamp,
                    "number_observed": 1,
                    "objects": {
                        "0": {
                            "type": "email-message",
                            "from_ref": "1",
                            "subject": scan_data.get("subject", "No subject")
                        },
                        "1": {
                            "type": "email-addr",
                            "value": scan_data.get("sender_email", "")
                        }
                    }
                }
            ]
        }
        return stix_bundle

    @staticmethod
    def export_siem_event(scan_data: Dict[str, Any], format_type: str = "splunk") -> Dict[str, Any]:
        """Generate SIEM syslog / event payload for Splunk or Elasticsearch."""
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        if format_type.lower() == "splunk":
            return {
                "event": {
                    "time": timestamp,
                    "source": "phishtrace:threat:email",
                    "sourcetype": "email:security",
                    "host": "phishtrace-gateway-01",
                    "action": "blocked" if scan_data.get("risk_score", 0) >= 60 else "allowed",
                    "risk_score": scan_data.get("risk_score", 0),
                    "risk_level": scan_data.get("risk_level", "LOW"),
                    "src_user": scan_data.get("sender_email"),
                    "src_ip": scan_data.get("origin_ip"),
                    "src_country": scan_data.get("geo_country"),
                    "src_infra": scan_data.get("infra_type"),
                    "subject": scan_data.get("subject"),
                    "spf": scan_data.get("spf_result"),
                    "dkim": scan_data.get("dkim_result"),
                    "dmarc": scan_data.get("dmarc_result"),
                    "evidence_hash": scan_data.get("evidence_hash"),
                    "vendor_product": "PhishTrace Enterprise Defense",
                    "mitre_technique": "T1566.001 - Spearphishing Attachment / Link"
                }
            }
        else:
            # Elastic Common Schema (ECS)
            return {
                "@timestamp": timestamp,
                "event": {
                    "kind": "alert",
                    "category": ["network", "threat"],
                    "type": ["indicator"],
                    "severity": scan_data.get("risk_score", 0),
                    "outcome": "failure" if scan_data.get("risk_score", 0) >= 60 else "success"
                },
                "source": {
                    "ip": scan_data.get("origin_ip"),
                    "geo": {
                        "country_name": scan_data.get("geo_country"),
                        "city_name": scan_data.get("geo_city")
                    }
                },
                "email": {
                    "from": {"address": [scan_data.get("sender_email")]},
                    "subject": scan_data.get("subject")
                },
                "threat": {
                    "framework": "MITRE ATT&CK",
                    "tactic": {"name": "Initial Access", "id": "TA0001"},
                    "technique": {"name": "Phishing", "id": "T1566"}
                }
            }
