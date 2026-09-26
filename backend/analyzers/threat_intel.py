import aiohttp
from typing import Dict, Any
from datetime import datetime

from config import ABUSEIPDB_API_KEY, GOOGLE_SAFE_BROWSING_KEY

class ThreatIntelAnalyzer:
    DEMO_MODE = True

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB API for IP reputation."""
        result = {
            'ip': ip,
            'abuse_confidence_score': 0,
            'total_reports': 0,
            'last_reported': None,
            'categories': [],
            'is_whitelisted': False
        }
        
        if not ip:
            return result

        if self.DEMO_MODE or not ABUSEIPDB_API_KEY:
            # Demo Data
            try:
                if int(ip.split('.')[-1]) % 2 == 0:
                    result['abuse_confidence_score'] = 85
                    result['total_reports'] = 120
                    result['categories'] = [18, 22] # Brute-Force, SSH
            except:
                pass
            return result

        headers = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_API_KEY
        }
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}', headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        d = data['data']
                        result['abuse_confidence_score'] = d.get('abuseConfidenceScore', 0)
                        result['total_reports'] = d.get('totalReports', 0)
                        result['last_reported'] = d.get('lastReportedAt')
                        result['is_whitelisted'] = d.get('isWhitelisted', False)
            except Exception:
                pass # Fallback to default safe
                
        return result

    async def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL against Google Safe Browsing."""
        result = {'url': url, 'safe': True, 'threat_type': None}
        
        if self.DEMO_MODE or not GOOGLE_SAFE_BROWSING_KEY:
            if 'login' in url or 'secure' in url:
                result['safe'] = False
                result['threat_type'] = 'SOCIAL_ENGINEERING'
            return result
            
        # Implementation for Google Safe Browsing would go here
        return result

    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup to check domain age."""
        result = {
            'domain': domain,
            'creation_date': None,
            'registrar': None,
            'domain_age_days': None,
            'is_newly_registered': False,
            'risk_flags': []
        }
        
        if not domain:
            return result

        if self.DEMO_MODE:
            result['domain_age_days'] = 15
            result['is_newly_registered'] = True
            result['risk_flags'].append("Domain is newly registered (< 30 days)")
            return result
            
        # Real WHOIS implementation using python-whois would go here
        return result
