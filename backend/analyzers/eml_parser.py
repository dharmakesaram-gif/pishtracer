import re
import email
from email import policy
import hashlib
from typing import Dict, Any, List

class EMLParser:
    """
    Enterprise RFC 5322 MIME Email & Attachment Parser.
    Extracts headers, multipart text/html, attachments, computes cryptographic hashes,
    and identifies advanced evasion techniques.
    """
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.scr', '.vbs', '.js', '.bat', '.cmd', '.ps1', '.iso', 
        '.img', '.docm', '.xlsm', '.pptm', '.hta', '.cpl', '.jar', '.dll'
    }

    @staticmethod
    def parse_eml_bytes(raw_bytes: bytes) -> Dict[str, Any]:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        
        # Headers
        headers = {}
        for k, v in msg.items():
            headers[k] = str(v)

        from_header = str(msg.get('From', ''))
        sender_name, sender_email = EMLParser._parse_address(from_header)

        subject = str(msg.get('Subject', ''))
        to_header = str(msg.get('To', ''))
        date_header = str(msg.get('Date', ''))
        message_id = str(msg.get('Message-ID', ''))
        return_path = str(msg.get('Return-Path', ''))
        reply_to = str(msg.get('Reply-To', ''))
        auth_results = str(msg.get('Authentication-Results', ''))

        # Body parsing
        text_body = ""
        html_body = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get_content_disposition() or '')

                if content_disposition == 'attachment' or part.get_filename():
                    att = EMLParser._process_attachment(part)
                    if att:
                        attachments.append(att)
                elif content_type == 'text/plain' and not text_body:
                    try:
                        text_body = part.get_content()
                    except Exception:
                        payload = part.get_payload(decode=True)
                        text_body = payload.decode(errors='ignore') if payload else ""
                elif content_type == 'text/html' and not html_body:
                    try:
                        html_body = part.get_content()
                    except Exception:
                        payload = part.get_payload(decode=True)
                        html_body = payload.decode(errors='ignore') if payload else ""
        else:
            try:
                text_body = msg.get_content()
            except Exception:
                payload = msg.get_payload(decode=True)
                text_body = payload.decode(errors='ignore') if payload else ""

        # Extract URLs
        all_text = f"{text_body} {html_body}"
        extracted_urls = EMLParser._extract_and_defang_urls(all_text)

        # Raw headers string
        raw_headers_str = "\n".join(f"{k}: {v}" for k, v in msg.items())

        return {
            "sender_name": sender_name,
            "sender_email": sender_email,
            "to": to_header,
            "subject": subject,
            "date": date_header,
            "message_id": message_id,
            "return_path": return_path,
            "reply_to": reply_to,
            "auth_results": auth_results,
            "body_text": text_body[:8000],
            "body_html": html_body[:15000],
            "raw_headers": raw_headers_str,
            "urls": extracted_urls,
            "attachments": attachments,
            "attachment_count": len(attachments),
            "has_high_risk_attachment": any(a['is_malicious_ext'] or a['is_double_extension'] for a in attachments)
        }

    @staticmethod
    def _parse_address(addr_str: str) -> (str, str):
        if not addr_str:
            return "", ""
        match = re.search(r'^(.*?)\s*<([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)>', addr_str.strip())
        if match:
            name = match.group(1).strip('"\'; ')
            email_addr = match.group(2).strip().lower()
            return name, email_addr
        email_match = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', addr_str)
        if email_match:
            return "", email_match.group(1).lower()
        return addr_str, ""

    @staticmethod
    def _process_attachment(part) -> Dict[str, Any]:
        filename = part.get_filename() or "unnamed_attachment"
        payload = part.get_payload(decode=True)
        if payload is None:
            return None

        sha256 = hashlib.sha256(payload).hexdigest()
        md5 = hashlib.md5(payload).hexdigest()
        size_bytes = len(payload)
        mime = part.get_content_type()

        # Check for dangerous extensions
        lower_name = filename.lower()
        is_malicious = any(lower_name.endswith(ext) for ext in EMLParser.SUSPICIOUS_EXTENSIONS)
        
        # Check for double extensions (e.g., pdf.exe)
        parts = lower_name.split('.')
        is_double = len(parts) > 2 and ('.' + parts[-1]) in EMLParser.SUSPICIOUS_EXTENSIONS

        return {
            "filename": filename,
            "size_bytes": size_bytes,
            "size_formatted": f"{size_bytes / 1024:.1f} KB" if size_bytes < 1048576 else f"{size_bytes / 1048576:.2f} MB",
            "mime_type": mime,
            "sha256": sha256,
            "md5": md5,
            "is_malicious_ext": is_malicious,
            "is_double_extension": is_double,
            "threat_verdict": "CRITICAL" if (is_malicious or is_double) else "SAFE_TYPE"
        }

    @staticmethod
    def _extract_and_defang_urls(text: str) -> List[Dict[str, str]]:
        url_regex = re.compile(r'https?://[^\s<>"\',;]+', re.IGNORECASE)
        found = list(set(url_regex.findall(text)))[:25]
        results = []
        for u in found:
            # Defang URL (standard cyber forensics practice: hxxps://domain[.]com)
            defanged = u.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]", 1)
            results.append({
                "original": u,
                "defanged": defanged,
                "is_ip_host": bool(re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u))
            })
        return results
