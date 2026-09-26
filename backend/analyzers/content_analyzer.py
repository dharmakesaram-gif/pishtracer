import re
from typing import Dict, Any

class ContentAnalyzer:
    BRAND_DOMAINS = [
        'paypal', 'amazon', 'microsoft', 'apple', 'google', 
        'netflix', 'icici', 'hdfc', 'sbi', 'irctc'
    ]
    URGENCY_CUES = [
        'urgent', 'immediate action required', 'account suspended', 
        'verify your identity', 'security alert', 'unauthorized access'
    ]
    FRAUD_INDICATORS = [
        'wire transfer', 'gift card', 'bitcoin', 'crypto', 'invoice attached'
    ]

    def analyze(self, sender_name: str, sender_email: str, subject: str, body_text: str) -> Dict[str, Any]:
        """
        Analyze email content for impersonation, urgency, and fraud indicators.
        """
        results = {
            'brand_impersonation': {'detected': False, 'brand': None, 'actual_domain': None},
            'typosquat': {'detected': False, 'target': None, 'similarity': 0},
            'urgency_hits': [],
            'fraud_indicators': [],
            'suspicious_urls': [],
            'score_contribution': 0,
            'reasons': []
        }
        
        sender_name = (sender_name or "").lower()
        subject = (subject or "").lower()
        body_text = (body_text or "").lower()
        
        # 1. Brand Impersonation
        if sender_email:
            domain = sender_email.split('@')[-1] if '@' in sender_email else sender_email
            for brand in self.BRAND_DOMAINS:
                if brand in sender_name and brand not in domain:
                    results['brand_impersonation'] = {
                        'detected': True,
                        'brand': brand,
                        'actual_domain': domain
                    }
                    results['score_contribution'] += 30
                    results['reasons'].append(f"Sender name implies {brand} but domain is {domain}")
                    break

        # 2. Urgency Cues
        for cue in self.URGENCY_CUES:
            if cue in subject or cue in body_text:
                results['urgency_hits'].append(cue)
                
        if results['urgency_hits']:
            results['score_contribution'] += min(20, len(results['urgency_hits']) * 10)
            results['reasons'].append("Urgency/Fear social engineering cues detected")

        # 3. Fraud Indicators
        for ind in self.FRAUD_INDICATORS:
            if ind in subject or ind in body_text:
                results['fraud_indicators'].append(ind)
                
        if results['fraud_indicators']:
            results['score_contribution'] += min(30, len(results['fraud_indicators']) * 15)
            results['reasons'].append("Financial fraud keywords detected")

        # 4. URLs
        url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
        urls = url_pattern.findall(body_text)
        for url in urls:
            if len(url) > 80 or any(short in url for short in ['bit.ly', 'tinyurl']):
                results['suspicious_urls'].append(url)
                
        if results['suspicious_urls']:
            results['score_contribution'] += 15
            results['reasons'].append("Suspicious URLs (long or shorteners) found in body")

        return results
