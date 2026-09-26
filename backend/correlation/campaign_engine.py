import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from uuid import uuid4
from difflib import SequenceMatcher

try:
    import networkx as nx
except ImportError:
    nx = None

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


class CampaignCorrelator:
    """Graph-based campaign correlation engine using NetworkX."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def correlate(self, scan_result) -> Optional[str]:
        """
        Correlate a new scan result against existing scans to detect campaigns.
        Returns campaign_id if the scan belongs to an existing or new campaign.
        """
        from database.models import ScanResult, Campaign
        
        # Get recent scans from the database (last 7 days)
        cutoff = datetime.utcnow() - timedelta(days=7)
        result = await self.db.execute(
            select(ScanResult).where(ScanResult.timestamp >= cutoff)
        )
        recent_scans = result.scalars().all()
        
        if not recent_scans:
            return None
        
        matches = []
        
        for existing_scan in recent_scans:
            if existing_scan.id == getattr(scan_result, 'id', None):
                continue
                
            similarity_score = 0
            
            # 1. Domain clustering: same sender domain
            if (scan_result.sender_domain and existing_scan.sender_domain and 
                scan_result.sender_domain == existing_scan.sender_domain):
                similarity_score += 40
            
            # 2. IP clustering: same origin IP
            if (scan_result.origin_ip and existing_scan.origin_ip and 
                scan_result.origin_ip == existing_scan.origin_ip):
                similarity_score += 30
            
            # 3. ASN clustering: same ASN
            if (scan_result.asn and existing_scan.asn and 
                scan_result.asn == existing_scan.asn):
                similarity_score += 20
            
            # 4. Subject similarity
            if scan_result.subject and existing_scan.subject:
                ratio = SequenceMatcher(None, 
                    scan_result.subject.lower(), 
                    existing_scan.subject.lower()
                ).ratio()
                if ratio > 0.6:
                    similarity_score += int(ratio * 30)
            
            # 5. Temporal clustering: within 2 hours
            if existing_scan.timestamp:
                time_diff = abs((datetime.utcnow() - existing_scan.timestamp).total_seconds())
                if time_diff < 7200:  # 2 hours
                    similarity_score += 15
            
            if similarity_score >= 40:
                matches.append({
                    'scan': existing_scan,
                    'score': similarity_score
                })
        
        if not matches:
            return None
        
        # Check if any match already belongs to a campaign
        for match in sorted(matches, key=lambda x: x['score'], reverse=True):
            if match['scan'].campaign_id:
                # Add to existing campaign
                campaign_result = await self.db.execute(
                    select(Campaign).where(Campaign.id == match['scan'].campaign_id)
                )
                campaign = campaign_result.scalar_one_or_none()
                if campaign:
                    campaign.last_seen = datetime.utcnow()
                    campaign.scan_count += 1
                    # Update domains list
                    domains = json.loads(campaign.domains or '[]')
                    if scan_result.sender_domain and scan_result.sender_domain not in domains:
                        domains.append(scan_result.sender_domain)
                        campaign.domains = json.dumps(domains)
                    # Update IPs list
                    ips = json.loads(campaign.ips or '[]')
                    if scan_result.origin_ip and scan_result.origin_ip not in ips:
                        ips.append(scan_result.origin_ip)
                        campaign.ips = json.dumps(ips)
                    return campaign.id
        
        # Create new campaign if 3+ matches
        if len(matches) >= 2:
            domains = list(set(filter(None, [scan_result.sender_domain] + 
                [m['scan'].sender_domain for m in matches])))
            ips = list(set(filter(None, [scan_result.origin_ip] + 
                [m['scan'].origin_ip for m in matches])))
            
            campaign = Campaign(
                id=str(uuid4()),
                name=self._auto_name_campaign(scan_result, matches),
                first_seen=min(m['scan'].timestamp for m in matches if m['scan'].timestamp) if matches else datetime.utcnow(),
                last_seen=datetime.utcnow(),
                scan_count=len(matches) + 1,
                domains=json.dumps(domains),
                ips=json.dumps(ips),
                risk_level='HIGH' if any(m['scan'].risk_score >= 60 for m in matches) else 'MEDIUM'
            )
            self.db.add(campaign)
            
            # Update all matched scans to belong to this campaign
            for match in matches:
                match['scan'].campaign_id = campaign.id
            
            return campaign.id
        
        return None

    def _auto_name_campaign(self, scan_result, matches: list) -> str:
        """Generate a human-readable campaign name."""
        domains = list(set(filter(None, [scan_result.sender_domain] + 
            [m['scan'].sender_domain for m in matches])))
        
        # Check for brand impersonation
        brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'netflix']
        for brand in brands:
            subject_text = (scan_result.subject or '').lower()
            if brand in subject_text or any(brand in (m['scan'].subject or '').lower() for m in matches):
                return f"Brand Impersonation Wave (targeting {brand.title()} users)"
        
        # Check for invoice/financial fraud
        financial_terms = ['invoice', 'payment', 'transfer', 'bank']
        if any(term in (scan_result.subject or '').lower() for term in financial_terms):
            primary_domain = domains[0] if domains else 'unknown'
            return f"Invoice Fraud Cluster ({primary_domain})"
        
        # Generic campaign name
        if len(domains) > 1:
            return f"Coordinated Phishing Ring ({len(domains)} domains)"
        elif domains:
            return f"Phishing Campaign ({domains[0]})"
        else:
            return f"Threat Cluster #{str(uuid4())[:8]}"

    def get_campaign_graph(self, campaign_id: str, scans: list) -> Dict[str, Any]:
        """Return a graph structure suitable for visualization."""
        nodes = []
        edges = []
        seen_domains = set()
        seen_ips = set()
        
        for scan in scans:
            if scan.campaign_id != campaign_id:
                continue
            
            # Email node
            email_node_id = f"email:{scan.id}"
            nodes.append({
                'id': email_node_id,
                'type': 'email',
                'label': (scan.subject or 'No subject')[:40],
                'risk': scan.risk_level.lower() if scan.risk_level else 'low'
            })
            
            # Domain node
            if scan.sender_domain and scan.sender_domain not in seen_domains:
                seen_domains.add(scan.sender_domain)
                nodes.append({
                    'id': f"domain:{scan.sender_domain}",
                    'type': 'domain',
                    'label': scan.sender_domain,
                    'risk': 'high' if scan.risk_score >= 60 else 'medium'
                })
            if scan.sender_domain:
                edges.append({
                    'source': email_node_id,
                    'target': f"domain:{scan.sender_domain}",
                    'label': 'sent-from'
                })
            
            # IP node
            if scan.origin_ip and scan.origin_ip not in seen_ips:
                seen_ips.add(scan.origin_ip)
                nodes.append({
                    'id': f"ip:{scan.origin_ip}",
                    'type': 'ip',
                    'label': scan.origin_ip,
                    'risk': 'high' if scan.infra_type in ['VPN', 'TOR'] else 'medium'
                })
            if scan.origin_ip:
                edges.append({
                    'source': f"domain:{scan.sender_domain}" if scan.sender_domain else email_node_id,
                    'target': f"ip:{scan.origin_ip}",
                    'label': 'hosted-on'
                })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'campaign_id': campaign_id
        }
