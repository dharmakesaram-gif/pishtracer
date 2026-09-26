import re
from typing import Dict, Any, List

class HeaderAnalyzer:
    def __init__(self):
        self.private_ip_pattern = re.compile(
            r'^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
            r'192\.168\.\d{1,3}\.\d{1,3}|'
            r'172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|'
            r'127\.\d{1,3}\.\d{1,3})$'
        )

    def analyze(self, raw_headers: str) -> Dict[str, Any]:
        """
        Analyze raw email headers to extract domains, IPs, and authentication results.
        """
        if not raw_headers:
            return {}

        results = {
            'from_domain': None,
            'return_path_domain': None,
            'reply_to_domain': None,
            'spf': None,
            'dkim': None,
            'dmarc': None,
            'origin_ip': None,
            'all_ips': [],
            'relay_hops': 0,
            'mismatches': [],
            'score_contribution': 0
        }
        
        # Simple extraction logic (mocked for brevity, but functional structure)
        lines = raw_headers.split('\n')
        for line in lines:
            line_lower = line.lower()
            if line_lower.startswith('from:'):
                results['from_domain'] = self._extract_domain(line)
            elif line_lower.startswith('return-path:'):
                results['return_path_domain'] = self._extract_domain(line)
            elif line_lower.startswith('reply-to:'):
                results['reply_to_domain'] = self._extract_domain(line)
            elif 'spf=' in line_lower:
                results['spf'] = 'pass' if 'pass' in line_lower else 'fail'
            elif 'dkim=' in line_lower:
                results['dkim'] = 'pass' if 'pass' in line_lower else 'fail'
            elif 'dmarc=' in line_lower:
                results['dmarc'] = 'pass' if 'pass' in line_lower else 'fail'
                
        # Domain Mismatches
        if results['from_domain'] and results['return_path_domain'] and results['from_domain'] != results['return_path_domain']:
            results['mismatches'].append('From and Return-Path domains mismatch')
            results['score_contribution'] += 20
            
        if results['from_domain'] and results['reply_to_domain'] and results['from_domain'] != results['reply_to_domain']:
            results['mismatches'].append('From and Reply-To domains mismatch')
            results['score_contribution'] += 20
            
        # Auth failures
        for auth in ['spf', 'dkim', 'dmarc']:
            if results[auth] == 'fail':
                results['score_contribution'] += 15

        # Extract IPs using regex
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        found_ips = ip_pattern.findall(raw_headers)
        
        for ip in found_ips:
            if not self.private_ip_pattern.match(ip) and ip not in results['all_ips']:
                results['all_ips'].append(ip)
                
        results['relay_hops'] = len(results['all_ips'])
        if results['all_ips']:
            results['origin_ip'] = results['all_ips'][-1] # Simplistic: last non-private IP
            
        return results
        
    def _extract_domain(self, header_line: str) -> str:
        match = re.search(r'@([\w.-]+\.[a-zA-Z]{2,})', header_line)
        return match.group(1).lower() if match else None
