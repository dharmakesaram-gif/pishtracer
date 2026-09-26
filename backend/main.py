import json
import hashlib
from typing import Optional, List
from collections import Counter
from fastapi import FastAPI, Depends, HTTPException, Query, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import Response, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from pydantic import BaseModel
import os

from database.database import get_db, init_db
from database.models import ScanResult, Campaign
from config import CORS_ORIGINS

from analyzers.header_analyzer import HeaderAnalyzer
from analyzers.content_analyzer import ContentAnalyzer
from analyzers.geo_analyzer import GeoAnalyzer
from analyzers.threat_intel import ThreatIntelAnalyzer
from analyzers.eml_parser import EMLParser
from correlation.campaign_engine import CampaignCorrelator
from reports.generator import ReportGenerator
from models.phishing_classifier import PhishingClassifier
from models.neural_net import PhishNetManager
from soar.playbooks import SOARPlaybooks

app = FastAPI(title="PhishTrace API", version="2.0.0",
              description="AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount dashboard static files
_dashboard_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dashboard')
os.makedirs(_dashboard_dir, exist_ok=True)
app.mount("/dashboard", StaticFiles(directory=_dashboard_dir, html=True), name="dashboard")

@app.on_event("startup")
async def startup_event():
    await init_db()
    print("PhishTrace API started. Dashboard at http://localhost:8000/dashboard")


class AnalyzeRequest(BaseModel):
    raw_headers: Optional[str] = None
    sender_name: Optional[str] = None
    sender_email: Optional[str] = None
    subject: Optional[str] = None
    body_text: Optional[str] = None
    urls: Optional[List[str]] = []


@app.post("/api/analyze")
async def analyze_email(req: AnalyzeRequest, db: AsyncSession = Depends(get_db)):
    """Analyze an email for phishing, spoofing, and BEC indicators."""
    header_analyzer = HeaderAnalyzer()
    content_analyzer = ContentAnalyzer()
    geo_analyzer = GeoAnalyzer()
    threat_intel = ThreatIntelAnalyzer()
    correlator = CampaignCorrelator(db)

    reasons = []
    total_score = 0
    domain_to_check = None

    # ---- 1. Header Analysis ----
    h_res = {}
    try:
        h_res = header_analyzer.analyze(req.raw_headers or "")
        total_score += h_res.get('score_contribution', 0)
        reasons.extend(h_res.get('mismatches', []))
    except Exception as e:
        print(f"Header analysis error: {e}")

    # ---- 2. Content Analysis ----
    c_res = {}
    try:
        c_res = content_analyzer.analyze(req.sender_name, req.sender_email, req.subject, req.body_text)
        total_score += c_res.get('score_contribution', 0)
        reasons.extend(c_res.get('reasons', []))
    except Exception as e:
        print(f"Content analysis error: {e}")

    # ---- 3. Geo Analysis ----
    origin_ip = h_res.get('origin_ip')
    geo_res = {}
    if origin_ip:
        try:
            geo_res = await geo_analyzer.analyze(origin_ip)
            reasons.extend(geo_res.get('risk_flags', []))
            if geo_res.get('infra_type') in ['VPN', 'TOR']:
                total_score += 25
            elif geo_res.get('infra_type') == 'DATACENTER':
                total_score += 10
        except Exception as e:
            print(f"Geo analysis error: {e}")

    # ---- 4. Threat Intelligence ----
    ti_ip_res = {}
    ti_dom_res = {}
    try:
        if origin_ip:
            ti_ip_res = await threat_intel.check_ip(origin_ip)
            abuse_score = ti_ip_res.get('abuse_confidence_score', 0)
            if abuse_score > 50:
                total_score += 30
                reasons.append(f"IP has high abuse score: {abuse_score}/100 ({ti_ip_res.get('total_reports', 0)} reports)")

        domain_to_check = (h_res.get('from_domain') or
                           (req.sender_email.split('@')[-1] if req.sender_email and '@' in req.sender_email else None))
        if domain_to_check:
            ti_dom_res = await threat_intel.check_domain(domain_to_check)
            reasons.extend(ti_dom_res.get('risk_flags', []))
            if ti_dom_res.get('is_newly_registered'):
                total_score += 20
    except Exception as e:
        print(f"Threat intel error: {e}")

    # ---- 5. Machine Learning & PyTorch Deep Neural Network ----
    ml_res = {}
    nn_res = {}
    try:
        classifier = PhishingClassifier()
        ml_features = classifier.extract_features({
            'subject': req.subject or '',
            'body': req.body_text or '',
            'urls': req.urls or [],
            'sender': req.sender_name or '',
            'sender_email': req.sender_email or '',
        })
        ml_res = classifier.predict(ml_features)
        rf_prob = ml_res.get('phishing_probability', 0.0)

        # PyTorch PhishNet Forward Pass
        nn_manager = PhishNetManager()
        feat_vec = [
            ml_features.get('subject_length', 0), ml_features.get('body_length', 0), ml_features.get('num_urls', 0),
            ml_features.get('num_ip_urls', 0), int(ml_features.get('has_html', False)), ml_features.get('urgency_word_count', 0),
            ml_features.get('financial_word_count', 0), int(ml_features.get('brand_name_in_sender', False)),
            int(ml_features.get('domain_mismatch', False)), int(ml_features.get('has_attachment_mention', False)),
            int(ml_features.get('greeting_generic', False)), int(ml_features.get('reply_to_mismatch', False)),
            ml_features.get('num_exclamation', 0), ml_features.get('all_caps_ratio', 0.0), int(ml_features.get('suspicious_tld', False))
        ]
        full_text = (req.subject or '') + ' ' + (req.body_text or '')
        nn_res = nn_manager.predict(feat_vec, full_text)
        nn_prob = nn_res.get('neural_network_probability', 0.0)

        # Hybrid AI Fusion: 50% Random Forest + 50% PyTorch Deep Neural Net
        blended_prob = (rf_prob * 0.5) + (nn_prob * 0.5)
        if blended_prob >= 0.5:
            total_score += int(blended_prob * 25)
            reasons.append(f"PyTorch Deep Neural Network (PhishNet): Flagged threat with {int(nn_prob * 100)}% neural confidence")
            if ml_res.get('explanation'):
                reasons.append(f"AI Classifier Ensemble: {ml_res['explanation']}")
    except Exception as e:
        print(f"ML / Neural Network error: {e}")

    # ---- Compute final score ----
    risk_score = min(total_score, 100)
    if risk_score >= 80:
        risk_level = 'CRITICAL'
    elif risk_score >= 60:
        risk_level = 'HIGH'
    elif risk_score >= 30:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'

    # Evidence hash (tamper-evident)
    evidence_str = json.dumps({
        'ip': origin_ip, 'email': req.sender_email,
        'subject': req.subject, 'score': risk_score,
        'reasons': reasons
    }, sort_keys=True)
    evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()

    # ---- Persist to database ----
    scan = ScanResult(
        sender_name=req.sender_name,
        sender_email=req.sender_email,
        sender_domain=domain_to_check,
        subject=req.subject,
        body_snippet=(req.body_text[:500] if req.body_text else None),
        risk_score=risk_score,
        risk_level=risk_level,
        reasons=json.dumps(reasons),
        from_domain=h_res.get('from_domain'),
        return_path_domain=h_res.get('return_path_domain'),
        spf_result=h_res.get('spf'),
        dkim_result=h_res.get('dkim'),
        dmarc_result=h_res.get('dmarc'),
        origin_ip=origin_ip,
        geo_country=geo_res.get('country'),
        geo_city=geo_res.get('city'),
        geo_lat=geo_res.get('latitude'),
        geo_lon=geo_res.get('longitude'),
        asn=geo_res.get('asn_org'),
        infra_type=geo_res.get('infra_type'),
        abuse_score=ti_ip_res.get('abuse_confidence_score'),
        evidence_hash=evidence_hash,
    )

    # ---- 5. Campaign Correlation ----
    try:
        scan.campaign_id = await correlator.correlate(scan)
    except Exception as e:
        print(f"Correlation error: {e}")

    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # ---- Return enriched response ----
    return {
        "status": "success",
        "scan_id": scan.id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "header_forensics": {
            "from_domain": h_res.get('from_domain'),
            "return_path_domain": h_res.get('return_path_domain'),
            "spf": h_res.get('spf'),
            "dkim": h_res.get('dkim'),
            "dmarc": h_res.get('dmarc'),
            "origin_ip": origin_ip,
            "relay_hops": h_res.get('relay_hops', 0),
        },
        "geo_data": {
            "ip": origin_ip,
            "country": geo_res.get('country'),
            "city": geo_res.get('city'),
            "latitude": geo_res.get('latitude'),
            "longitude": geo_res.get('longitude'),
            "asn_org": geo_res.get('asn_org'),
            "infra_type": geo_res.get('infra_type'),
            "abuse_confidence_score": ti_ip_res.get('abuse_confidence_score'),
        },
        "content_analysis": {
            "brand_impersonation": c_res.get('brand_impersonation', {}),
            "urgency_hits": c_res.get('urgency_hits', []),
            "fraud_indicators": c_res.get('fraud_indicators', []),
            "suspicious_urls": c_res.get('suspicious_urls', []),
        },
        "threat_intel": {
            "domain_age_days": ti_dom_res.get('domain_age_days'),
            "is_newly_registered": ti_dom_res.get('is_newly_registered', False),
        },
        "ai_analysis": ml_res,
        "neural_network": nn_res,
        "campaign_id": scan.campaign_id,
        "evidence_hash": evidence_hash,
    }


def _scan_to_dict(scan: ScanResult) -> dict:
    """Convert a ScanResult ORM object to a JSON-safe dict."""
    reasons_raw = scan.reasons
    if isinstance(reasons_raw, str):
        try:
            reasons = json.loads(reasons_raw)
        except (json.JSONDecodeError, TypeError):
            reasons = [reasons_raw] if reasons_raw else []
    else:
        reasons = reasons_raw or []

    return {
        "id": scan.id,
        "timestamp": scan.timestamp.isoformat() + "Z" if scan.timestamp else None,
        "sender_name": scan.sender_name,
        "sender_email": scan.sender_email,
        "sender_domain": scan.sender_domain,
        "subject": scan.subject,
        "body_snippet": scan.body_snippet,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "reasons": reasons,
        "from_domain": scan.from_domain,
        "return_path_domain": scan.return_path_domain,
        "spf_result": scan.spf_result,
        "dkim_result": scan.dkim_result,
        "dmarc_result": scan.dmarc_result,
        "origin_ip": scan.origin_ip,
        "sender": scan.sender_email or scan.sender_name or "Unknown",
        "sender_ip": scan.origin_ip or "N/A",
        "ai_explanation": (reasons[0] if reasons else "No risk indicators found."),
        "authentication": {
            "spf": scan.spf_result or "none",
            "dkim": scan.dkim_result or "none",
            "dmarc": scan.dmarc_result or "none"
        },
        "geo_country": scan.geo_country,
        "geo_city": scan.geo_city,
        "geo_lat": scan.geo_lat,
        "geo_lon": scan.geo_lon,
        "asn": scan.asn,
        "infra_type": scan.infra_type,
        "abuse_score": scan.abuse_score,
        "campaign_id": scan.campaign_id,
        "evidence_hash": scan.evidence_hash,
    }


@app.get("/api/scans")
async def list_scans(
    limit: int = 50, offset: int = 0, min_score: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """List scan results, most recent first."""
    query = (select(ScanResult)
             .where(ScanResult.risk_score >= min_score)
             .order_by(desc(ScanResult.timestamp))
             .offset(offset).limit(limit))
    res = await db.execute(query)
    scans = res.scalars().all()
    return [_scan_to_dict(s) for s in scans]


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get full details of a specific scan."""
    query = select(ScanResult).where(ScanResult.id == scan_id)
    res = await db.execute(query)
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_to_dict(scan)


@app.get("/api/scans/{scan_id}/report")
async def get_scan_report(
    scan_id: str, format: str = Query("json"),
    db: AsyncSession = Depends(get_db)
):
    """Generate a forensic report (PDF or JSON)."""
    query = select(ScanResult).where(ScanResult.id == scan_id)
    res = await db.execute(query)
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if format == "pdf":
        pdf_bytes = ReportGenerator.generate_pdf(scan)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=PhishTrace_Report_{scan_id[:8]}.pdf"}
        )
    return ReportGenerator.generate_json(scan)


@app.get("/api/campaigns")
async def get_campaigns(db: AsyncSession = Depends(get_db)):
    """List detected threat campaigns."""
    res = await db.execute(select(Campaign).order_by(desc(Campaign.last_seen)))
    campaigns = res.scalars().all()
    result = []
    for c in campaigns:
        result.append({
            "id": c.id,
            "name": c.name,
            "first_seen": c.first_seen.isoformat() + "Z" if c.first_seen else None,
            "last_seen": c.last_seen.isoformat() + "Z" if c.last_seen else None,
            "scan_count": c.scan_count,
            "domains": json.loads(c.domains) if c.domains else [],
            "ips": json.loads(c.ips) if c.ips else [],
            "risk_level": c.risk_level,
        })
    return result


@app.get("/api/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    """Dashboard statistics."""
    res = await db.execute(select(ScanResult).order_by(desc(ScanResult.timestamp)))
    scans = res.scalars().all()

    total = len(scans)
    flagged = sum(1 for s in scans if s.risk_score >= 30)
    high_risk = sum(1 for s in scans if s.risk_level in ('HIGH', 'CRITICAL'))

    # Top sender domains
    domain_counts = Counter(s.sender_domain for s in scans if s.sender_domain)
    top_domains = [{"domain": d, "count": c} for d, c in domain_counts.most_common(10)]

    # Geo distribution
    geo_dist = []
    for s in scans:
        if s.geo_lat and s.geo_lon:
            geo_dist.append({
                "id": s.id,
                "ip": s.origin_ip or "Unknown",
                "lat": s.geo_lat,
                "lon": s.geo_lon,
                "country": s.geo_country,
                "city": s.geo_city,
                "risk_score": s.risk_score,
                "avg_score": s.risk_score,
                "count": 1,
                "infra_type": s.infra_type,
            })

    # Risk level distribution
    risk_dist = Counter(s.risk_level for s in scans)

    # Campaign count
    camp_res = await db.execute(select(Campaign))
    campaign_count = len(camp_res.scalars().all())

    return {
        "total_scans": total,
        "total_flagged": flagged,
        "high_risk_count": high_risk,
        "campaign_count": campaign_count,
        "risk_distribution": {
            "LOW": risk_dist.get('LOW', 0),
            "MEDIUM": risk_dist.get('MEDIUM', 0),
            "HIGH": risk_dist.get('HIGH', 0),
            "CRITICAL": risk_dist.get('CRITICAL', 0),
        },
        "top_sender_domains": top_domains,
        "geo_distribution": geo_dist,
        "recent_scans": [_scan_to_dict(s) for s in scans[:10]],
    }


# -------------------------------------------------------------
# Enterprise Real-World Endpoints: EML Ingestion & SOAR Response
# -------------------------------------------------------------

@app.post("/api/analyze/eml")
async def analyze_eml_file(file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    """
    Enterprise EML / MSG File Ingestion:
    Parses RFC 5322 MIME messages, extracts attachments, computes SHA-256 hashes,
    defangs URLs, and runs full Tri-Modal Hybrid AI detection.
    """
    content_bytes = await file.read()
    parsed = EMLParser.parse_eml_bytes(content_bytes)

    # Construct request
    req = AnalyzeRequest(
        raw_headers=parsed.get("raw_headers"),
        sender_name=parsed.get("sender_name"),
        sender_email=parsed.get("sender_email"),
        subject=parsed.get("subject"),
        body_text=parsed.get("body_text"),
        urls=[u["original"] for u in parsed.get("urls", [])]
    )

    # Run analysis
    result = await analyze_email(req, db)

    # Attach enterprise forensics
    result["attachments"] = parsed.get("attachments", [])
    result["defanged_urls"] = parsed.get("urls", [])
    result["message_id"] = parsed.get("message_id")
    result["body_html"] = parsed.get("body_html", "")

    # Elevate score if high-risk attachments exist
    if parsed.get("has_high_risk_attachment"):
        result["risk_score"] = 100
        result["risk_level"] = "CRITICAL"
        result["reasons"].insert(0, "🚨 CRITICAL EVASION: Malicious executable / macro-enabled attachment detected!")

    return result


@app.post("/api/soar/quarantine/{scan_id}")
async def quarantine_incident(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Execute SOAR quarantine playbook on flagged incident."""
    scan = await get_scan(scan_id, db)
    playbook_result = SOARPlaybooks.quarantine_message(scan)
    return playbook_result


@app.get("/api/soar/block-rules/{scan_id}")
async def get_firewall_rules(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Generate enterprise firewall & DNS sinkhole rules (iptables, RPZ, Cisco ACL)."""
    scan = await get_scan(scan_id, db)
    return SOARPlaybooks.generate_firewall_rules(scan)


@app.get("/api/scans/{scan_id}/stix")
async def export_stix_bundle(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Export OASIS STIX 2.1 JSON Cyber Threat Intelligence bundle."""
    scan = await get_scan(scan_id, db)
    bundle = SOARPlaybooks.generate_stix_bundle(scan)
    return JSONResponse(
        content=bundle,
        headers={"Content-Disposition": f"attachment; filename=stix21_threat_{scan_id[:8]}.json"}
    )


@app.get("/api/scans/{scan_id}/siem")
async def export_siem_event(
    scan_id: str, 
    format: str = Query("splunk", enum=["splunk", "elastic"]),
    db: AsyncSession = Depends(get_db)
):
    """Export incident event formatted for Splunk CIM or Elasticsearch ECS."""
    scan = await get_scan(scan_id, db)
    event = SOARPlaybooks.export_siem_event(scan, format_type=format)
    return JSONResponse(
        content=event,
        headers={"Content-Disposition": f"attachment; filename={format}_event_{scan_id[:8]}.json"}
    )

