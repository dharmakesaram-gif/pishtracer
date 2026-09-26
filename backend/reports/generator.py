import json
import hashlib
from io import BytesIO
from datetime import datetime
from typing import Dict, Any
from uuid import uuid4

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.colors import HexColor
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class ReportGenerator:
    """Generates forensic PDF and JSON reports for email threat analysis."""

    # Colors
    DARK_BG = HexColor('#0a0f1a') if REPORTLAB_AVAILABLE else None
    HEADER_BG = HexColor('#1e293b') if REPORTLAB_AVAILABLE else None
    GREEN = HexColor('#10b981') if REPORTLAB_AVAILABLE else None
    AMBER = HexColor('#f59e0b') if REPORTLAB_AVAILABLE else None
    RED = HexColor('#ef4444') if REPORTLAB_AVAILABLE else None
    DARK_RED = HexColor('#991b1b') if REPORTLAB_AVAILABLE else None
    BLUE = HexColor('#3b82f6') if REPORTLAB_AVAILABLE else None
    TEXT_COLOR = HexColor('#1e293b') if REPORTLAB_AVAILABLE else None
    MUTED = HexColor('#64748b') if REPORTLAB_AVAILABLE else None

    @staticmethod
    def _get_risk_color(score: int):
        if not REPORTLAB_AVAILABLE:
            return None
        if score >= 80: return ReportGenerator.DARK_RED
        if score >= 60: return ReportGenerator.RED
        if score >= 30: return ReportGenerator.AMBER
        return ReportGenerator.GREEN

    @staticmethod
    def _get_risk_label(score: int) -> str:
        if score >= 80: return 'CRITICAL'
        if score >= 60: return 'HIGH RISK'
        if score >= 30: return 'SUSPICIOUS'
        return 'LOW RISK'

    @staticmethod
    def generate_pdf(scan_data) -> bytes:
        """Generate a professional forensic report PDF using ReportLab."""
        if not REPORTLAB_AVAILABLE:
            return b'%PDF-1.4 ReportLab not installed'

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            leftMargin=25*mm, rightMargin=25*mm,
            topMargin=20*mm, bottomMargin=20*mm
        )

        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle', parent=styles['Title'],
            fontSize=24, textColor=ReportGenerator.TEXT_COLOR,
            spaceAfter=6, alignment=TA_CENTER
        )
        subtitle_style = ParagraphStyle(
            'Subtitle', parent=styles['Normal'],
            fontSize=12, textColor=ReportGenerator.MUTED,
            alignment=TA_CENTER, spaceAfter=20
        )
        heading_style = ParagraphStyle(
            'SectionHeading', parent=styles['Heading2'],
            fontSize=16, textColor=ReportGenerator.BLUE,
            spaceBefore=20, spaceAfter=10,
            borderWidth=1, borderColor=ReportGenerator.BLUE,
            borderPadding=5
        )
        body_style = ParagraphStyle(
            'BodyText', parent=styles['Normal'],
            fontSize=10, textColor=ReportGenerator.TEXT_COLOR,
            spaceAfter=6
        )
        code_style = ParagraphStyle(
            'Code', parent=styles['Normal'],
            fontSize=9, textColor=ReportGenerator.TEXT_COLOR,
            fontName='Courier', backColor=HexColor('#f1f5f9'),
            borderWidth=0.5, borderColor=HexColor('#e2e8f0'),
            borderPadding=4, spaceAfter=4
        )

        elements = []

        # --- Helper to safely get attributes ---
        def get(attr, default='N/A'):
            val = getattr(scan_data, attr, None) if hasattr(scan_data, attr) else (scan_data.get(attr) if isinstance(scan_data, dict) else None)
            return val if val is not None else default

        risk_score = get('risk_score', 0)
        report_id = f"PT-{str(uuid4())[:8].upper()}"
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

        # ==================== PAGE 1: Cover & Executive Summary ====================
        elements.append(Spacer(1, 40))
        elements.append(Paragraph('🛡️ PhishTrace', title_style))
        elements.append(Paragraph('Email Threat Forensic Report', subtitle_style))
        elements.append(HRFlowable(width='100%', thickness=2, color=ReportGenerator.BLUE))
        elements.append(Spacer(1, 20))

        # Report metadata table
        meta_data = [
            ['Report ID', report_id],
            ['Generated', timestamp],
            ['Scan ID', str(get('id', 'Unknown'))],
        ]
        meta_table = Table(meta_data, colWidths=[120, 350])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (0, -1), ReportGenerator.MUTED),
            ('TEXTCOLOR', (1, 0), (1, -1), ReportGenerator.TEXT_COLOR),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 30))

        # Risk Score Box
        risk_color = ReportGenerator._get_risk_color(risk_score)
        risk_label = ReportGenerator._get_risk_label(risk_score)
        risk_data = [[
            Paragraph(f'<font size="36" color="{risk_color.hexval()}">{risk_score}</font>', 
                     ParagraphStyle('RiskScore', alignment=TA_CENTER)),
            Paragraph(f'<font size="14" color="{risk_color.hexval()}"><b>{risk_label}</b></font><br/>'
                     f'<font size="10" color="{ReportGenerator.MUTED.hexval()}">out of 100</font>',
                     ParagraphStyle('RiskLabel', alignment=TA_LEFT, leading=18))
        ]]
        risk_table = Table(risk_data, colWidths=[120, 350])
        risk_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, 0), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOX', (0, 0), (-1, -1), 1, risk_color),
            ('BACKGROUND', (0, 0), (-1, -1), HexColor('#f8fafc')),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ]))
        elements.append(risk_table)
        elements.append(Spacer(1, 20))

        # Executive Summary
        elements.append(Paragraph('<b>Executive Summary</b>', heading_style))
        reasons_raw = get('reasons', '[]')
        if isinstance(reasons_raw, str):
            try: reasons = json.loads(reasons_raw)
            except: reasons = [reasons_raw]
        elif isinstance(reasons_raw, list):
            reasons = reasons_raw
        else:
            reasons = []
        
        summary_text = (f'This email from <b>{get("sender_email", "unknown sender")}</b> '
                       f'with subject "<i>{get("subject", "N/A")}</i>" '
                       f'received a threat score of <b>{risk_score}/100 ({risk_label})</b>. '
                       f'{len(reasons)} threat indicator(s) were identified.')
        elements.append(Paragraph(summary_text, body_style))
        
        if reasons:
            elements.append(Spacer(1, 8))
            elements.append(Paragraph('<b>Threat Indicators:</b>', body_style))
            for i, reason in enumerate(reasons, 1):
                r_text = reason if isinstance(reason, str) else str(reason)
                elements.append(Paragraph(f'  {i}. {r_text}', body_style))

        elements.append(PageBreak())

        # ==================== PAGE 2: Email Details & Authentication ====================
        elements.append(Paragraph('<b>Email Details & Authentication</b>', heading_style))
        
        email_data = [
            ['Field', 'Value'],
            ['Sender Name', str(get('sender_name'))],
            ['Sender Email', str(get('sender_email'))],
            ['Sender Domain', str(get('sender_domain'))],
            ['Subject', str(get('subject'))],
        ]
        email_table = Table(email_data, colWidths=[130, 340])
        email_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), ReportGenerator.BLUE),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8fafc')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(email_table)
        elements.append(Spacer(1, 20))

        # Authentication Results
        elements.append(Paragraph('<b>Header Authentication</b>', heading_style))
        
        def auth_status(val):
            if not val or val == 'N/A': return '— Not Available'
            return f'✅ PASS' if val.lower() == 'pass' else f'❌ FAIL'
        
        auth_data = [
            ['Protocol', 'Result', 'Status'],
            ['SPF (Sender Policy Framework)', str(get('spf_result', 'N/A')), auth_status(get('spf_result'))],
            ['DKIM (DomainKeys)', str(get('dkim_result', 'N/A')), auth_status(get('dkim_result'))],
            ['DMARC', str(get('dmarc_result', 'N/A')), auth_status(get('dmarc_result'))],
        ]
        auth_table = Table(auth_data, colWidths=[200, 100, 170])
        auth_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), ReportGenerator.BLUE),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8fafc')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(auth_table)
        elements.append(Spacer(1, 15))

        # Domain comparison
        elements.append(Paragraph('<b>Domain Verification</b>', body_style))
        elements.append(Paragraph(f'From Domain: <font name="Courier">{get("from_domain")}</font>', code_style))
        elements.append(Paragraph(f'Return-Path Domain: <font name="Courier">{get("return_path_domain")}</font>', code_style))
        
        from_dom = get('from_domain', '')
        rp_dom = get('return_path_domain', '')
        if from_dom and rp_dom and from_dom != rp_dom and from_dom != 'N/A' and rp_dom != 'N/A':
            elements.append(Paragraph(
                f'<font color="{ReportGenerator.RED.hexval()}"><b>⚠ MISMATCH:</b> '
                f'From domain does not match Return-Path domain</font>', body_style
            ))

        elements.append(PageBreak())

        # ==================== PAGE 3: Geolocation & Infrastructure ====================
        elements.append(Paragraph('<b>Geolocation & Infrastructure Intelligence</b>', heading_style))
        
        geo_data = [
            ['Property', 'Value'],
            ['Origin IP', str(get('origin_ip'))],
            ['Country', str(get('geo_country'))],
            ['City', str(get('geo_city'))],
            ['Coordinates', f"{get('geo_lat', '?')}, {get('geo_lon', '?')}"],
            ['ASN / Organization', str(get('asn'))],
            ['Infrastructure Type', str(get('infra_type'))],
            ['Abuse Score', str(get('abuse_score', 'N/A'))],
        ]
        geo_table = Table(geo_data, colWidths=[180, 290])
        geo_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), ReportGenerator.BLUE),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8fafc')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(geo_table)
        elements.append(Spacer(1, 15))

        # Infrastructure warnings
        infra = get('infra_type', '')
        if infra in ['VPN', 'TOR', 'DATACENTER']:
            elements.append(Paragraph(
                f'<font color="{ReportGenerator.RED.hexval()}"><b>⚠ WARNING:</b> '
                f'Email originated from {infra} infrastructure. '
                f'This is a significant risk indicator as legitimate business emails '
                f'rarely originate from {infra.lower()} services.</font>', body_style
            ))

        elements.append(PageBreak())

        # ==================== PAGE 4: Evidence Integrity ====================
        elements.append(Paragraph('<b>Evidence Integrity & Chain of Custody</b>', heading_style))
        
        evidence_hash = get('evidence_hash', 'Not computed')
        elements.append(Paragraph(f'<b>SHA-256 Evidence Hash:</b>', body_style))
        elements.append(Paragraph(f'{evidence_hash}', code_style))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(f'<b>Report Generated:</b> {timestamp}', body_style))
        elements.append(Paragraph(f'<b>Report ID:</b> {report_id}', body_style))
        elements.append(Spacer(1, 20))
        
        elements.append(HRFlowable(width='100%', thickness=1, color=ReportGenerator.MUTED))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(
            '<font size="8" color="#94a3b8"><i>This report was generated by PhishTrace — '
            'AI-Powered Email Threat Detection Platform. '
            'The evidence hash above can be used to verify the integrity of this report. '
            'Any modification to the underlying data will produce a different hash value. '
            'This report is provided for informational purposes and should be reviewed '
            'by qualified security personnel before taking action.</i></font>',
            body_style
        ))

        # Build PDF
        doc.build(elements)
        return buffer.getvalue()

    @staticmethod
    def generate_json(scan_data) -> Dict[str, Any]:
        """Return structured JSON forensic report."""
        def get(attr, default=None):
            val = getattr(scan_data, attr, None) if hasattr(scan_data, attr) else (scan_data.get(attr) if isinstance(scan_data, dict) else None)
            return val if val is not None else default

        reasons_raw = get('reasons', '[]')
        if isinstance(reasons_raw, str):
            try: reasons = json.loads(reasons_raw)
            except: reasons = [reasons_raw]
        elif isinstance(reasons_raw, list):
            reasons = reasons_raw
        else:
            reasons = []

        return {
            'metadata': {
                'report_id': f'PT-{str(uuid4())[:8].upper()}',
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'version': '2.0.0',
                'platform': 'PhishTrace'
            },
            'risk_assessment': {
                'score': get('risk_score', 0),
                'level': get('risk_level', 'LOW'),
                'reasons': reasons
            },
            'email_details': {
                'sender_name': get('sender_name'),
                'sender_email': get('sender_email'),
                'sender_domain': get('sender_domain'),
                'subject': get('subject'),
                'body_snippet': get('body_snippet')
            },
            'header_forensics': {
                'from_domain': get('from_domain'),
                'return_path_domain': get('return_path_domain'),
                'spf': get('spf_result'),
                'dkim': get('dkim_result'),
                'dmarc': get('dmarc_result')
            },
            'geolocation': {
                'origin_ip': get('origin_ip'),
                'country': get('geo_country'),
                'city': get('geo_city'),
                'latitude': get('geo_lat'),
                'longitude': get('geo_lon'),
                'asn': get('asn'),
                'infrastructure_type': get('infra_type')
            },
            'campaign_intelligence': {
                'campaign_id': get('campaign_id'),
            },
            'evidence_integrity': {
                'sha256_hash': get('evidence_hash'),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        }
