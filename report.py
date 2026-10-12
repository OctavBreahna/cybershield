import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from database import get_db_connection

CS_BLUE   = colors.HexColor("#3b82f6")
CS_DARK   = colors.HexColor("#0f172a")
CS_DARKER = colors.HexColor("#060a14")
CS_GRAY   = colors.HexColor("#94a3b8")
CS_WHITE  = colors.white
CS_GREEN  = colors.HexColor("#10b981")
CS_YELLOW = colors.HexColor("#f59e0b")
CS_ORANGE = colors.HexColor("#f97316")
CS_RED    = colors.HexColor("#ef4444")
CS_LINE   = colors.HexColor("#1e293b")

def score_color(score):
    if score >= 90: return CS_GREEN
    if score >= 70: return CS_YELLOW
    if score >= 40: return CS_ORANGE
    return CS_RED

def score_label(score):
    if score >= 90: return "EXCELLENT"
    if score >= 70: return "MEDIUM"
    if score >= 40: return "VULNERABLE"
    return "CRITICAL"

def get_latest_scan(client_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT score, ports, ssl, blacklist, scanned_at
        FROM scans WHERE client_id = %s
        ORDER BY scanned_at DESC LIMIT 1
    """, (client_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    return row

def get_client(client_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT name, domain, email FROM clients WHERE id = %s", (client_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    return row

def generate_report(client_id, output_dir="/home/cybersh/reports"):
    os.makedirs(output_dir, exist_ok=True)

    client = get_client(client_id)
    if not client:
        print(f"[ERROR] Client {client_id} not found.")
        return None
    name, domain, email = client

    scan = get_latest_scan(client_id)
    if not scan:
        print(f"[ERROR] No scan found for client {client_id}.")
        return None
    score, ports_raw, ssl_raw, blacklist_raw, scan_time = scan
    scan_data = {
        "ports": ports_raw if isinstance(ports_raw, list) else [],
        "ssl": ssl_raw if isinstance(ssl_raw, dict) else {},
        "blacklist": blacklist_raw if isinstance(blacklist_raw, dict) else {},
    }

    month_str = datetime.now().strftime("%B %Y")
    scan_str = scan_time.strftime("%d %b %Y %H:%M") if hasattr(scan_time, "strftime") else str(scan_time)
    filename = f"{output_dir}/report_{domain}_{datetime.now().strftime('%Y%m')}.pdf"

    doc = SimpleDocTemplate(
        filename, pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm,
        topMargin=15*mm, bottomMargin=15*mm
    )
    story = []
    W = 170*mm

    # ── HEADER ────────────────────────────────────────────────────────────────
    header_data = [[
        Paragraph("CyberShield", ParagraphStyle("logo", fontSize=26, textColor=CS_BLUE, fontName="Helvetica-Bold")),
        Paragraph(f"Security Report<br/><font size='9' color='#64748b'>{month_str}</font>",
                  ParagraphStyle("rdate", fontSize=13, textColor=CS_WHITE, alignment=TA_RIGHT, fontName="Helvetica-Bold")),
    ]]
    ht = Table(header_data, colWidths=[W*0.60, W*0.40])
    ht.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), CS_DARK),
        ("PADDING",    (0,0), (0,-1), 16),
        ("PADDING",    (1,0), (1,-1), 16),
        ("TOPPADDING",  (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",(0,0), (-1,-1), 14),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("LINEBELOW",  (0,0), (-1,-1), 2, CS_BLUE),
    ]))
    story.append(ht)
    story.append(Spacer(1, 5*mm))

    # ── CLIENT INFO ───────────────────────────────────────────────────────────
    info_data = [[
        Paragraph(f"<b>Client:</b> {name}", ParagraphStyle("ci", fontSize=11, textColor=CS_WHITE, fontName="Helvetica")),
        Paragraph(f"<b>Domain:</b> {domain}", ParagraphStyle("cd", fontSize=11, textColor=CS_WHITE, fontName="Helvetica")),
        Paragraph(f"<b>Scan date:</b> {scan_str}", ParagraphStyle("cs", fontSize=11, textColor=CS_WHITE, fontName="Helvetica", alignment=TA_RIGHT)),
    ]]
    it = Table(info_data, colWidths=[W*0.35, W*0.35, W*0.30])
    it.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), CS_DARKER),
        ("PADDING",    (0,0), (-1,-1), 10),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("LINEBELOW",  (0,0), (-1,-1), 1, CS_BLUE),
    ]))
    story.append(it)
    story.append(Spacer(1, 6*mm))

    # ── SECURITY SCORE ────────────────────────────────────────────────────────
    sc = score_color(score)
    score_data = [[
        Paragraph("SECURITY<br/>SCORE", ParagraphStyle("sl", fontSize=10, textColor=CS_GRAY, alignment=TA_CENTER, leading=14)),
        Paragraph(f"{score}/100", ParagraphStyle("sv", fontSize=24, textColor=sc, fontName="Helvetica-Bold", leading=24, alignment=TA_CENTER)),
        Paragraph(score_label(score), ParagraphStyle("ss", fontSize=16, textColor=sc, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(
            "No critical vulnerabilities<br/>detected. Continuous<br/>monitoring active." if score >= 90
            else "Some issues detected.<br/>Review recommendations<br/>below.",
            ParagraphStyle("sd", fontSize=9, textColor=CS_GRAY, alignment=TA_CENTER, leading=13)
        ),
    ]]
    st = Table(score_data, colWidths=[W*0.18, W*0.27, W*0.27, W*0.28])
    st.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), CS_DARK),
        ("PADDING",    (0,0), (-1,-1), 18),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("LINEBEFORE", (1,0), (1,-1), 1, CS_LINE),
        ("LINEBEFORE", (2,0), (2,-1), 1, CS_LINE),
        ("LINEBEFORE", (3,0), (3,-1), 1, CS_LINE),
        ("LINEABOVE",  (0,0), (-1,0), 2, sc),
        ("LINEBELOW",  (0,0), (-1,-1), 2, sc),
    ]))
    story.append(st)
    story.append(Spacer(1, 7*mm))

    def section_title(text):
        return Paragraph(text, ParagraphStyle("sh", fontSize=10, textColor=CS_BLUE,
                         fontName="Helvetica-Bold", spaceBefore=2, spaceAfter=4))

    # ── SSL ───────────────────────────────────────────────────────────────────
    story.append(section_title("SSL / HTTPS CERTIFICATE"))
    ssl = scan_data.get("ssl", {})
    ssl_valid = ssl.get("valid", False)
    ssl_days  = ssl.get("days_left", "N/A")
    ssl_exp   = ssl.get("expires", "N/A")
    ssl_color = CS_GREEN if ssl_valid else CS_RED
    ssl_rows = [
        ["Status", "Valid" if ssl_valid else "Invalid / Missing", "Days remaining", str(ssl_days)],
        ["Expires", str(ssl_exp), "Risk", "Low" if ssl_valid and isinstance(ssl_days,int) and ssl_days>30 else "High"],
    ]
    slt = Table(ssl_rows, colWidths=[W*0.20, W*0.30, W*0.20, W*0.30])
    slt.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), CS_DARK),
        ("BACKGROUND", (2,0), (2,-1), CS_DARK),
        ("BACKGROUND", (1,0), (1,-1), CS_DARKER),
        ("BACKGROUND", (3,0), (3,-1), CS_DARKER),
        ("TEXTCOLOR",  (0,0), (0,-1), CS_BLUE),
        ("TEXTCOLOR",  (2,0), (2,-1), CS_BLUE),
        ("TEXTCOLOR",  (1,0), (1,-1), CS_WHITE),
        ("TEXTCOLOR",  (3,0), (3,-1), CS_WHITE),
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
        ("PADDING",    (0,0), (-1,-1), 9),
        ("GRID",       (0,0), (-1,-1), 0.5, CS_LINE),
        ("LINEABOVE",  (0,0), (-1,0), 2, ssl_color),
    ]))
    story.append(slt)
    story.append(Spacer(1, 5*mm))

    # ── PORTS ─────────────────────────────────────────────────────────────────
    story.append(section_title("OPEN PORTS & SERVICES"))
    port_rows = [["Port", "Service", "Status", "Risk Level"]]
    ports = scan_data.get("ports", [])
    dangerous = {21:"FTP", 23:"Telnet", 3306:"MySQL", 5432:"PostgreSQL"}
    svc_map = {80:"HTTP",443:"HTTPS",22:"SSH",8080:"HTTP-Alt",8443:"HTTPS-Alt",
               21:"FTP",23:"Telnet",3306:"MySQL",5432:"PostgreSQL",25:"SMTP"}
    for p in ports:
        port = p.get("port","")
        state = p.get("state","")
        service = svc_map.get(port, "Unknown")
        if port in dangerous and state == "open":
            risk = "CRITICAL" if port in [23,3306,5432] else "HIGH"
        elif state == "open":
            risk = "Normal"
        else:
            risk = "Filtered"
        port_rows.append([str(port), service, state.upper(), risk])

    prt = Table(port_rows, colWidths=[W*0.15, W*0.30, W*0.25, W*0.30])
    prt.setStyle(TableStyle([
        ("BACKGROUND",     (0,0), (-1,0), CS_BLUE),
        ("TEXTCOLOR",      (0,0), (-1,0), CS_WHITE),
        ("FONTNAME",       (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",       (0,0), (-1,-1), 9),
        ("PADDING",        (0,0), (-1,-1), 8),
        ("GRID",           (0,0), (-1,-1), 0.5, CS_LINE),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [CS_DARKER, CS_DARK]),
        ("TEXTCOLOR",      (0,1), (-1,-1), CS_WHITE),
    ]))
    story.append(prt)
    story.append(Spacer(1, 5*mm))

    # ── BLACKLIST ─────────────────────────────────────────────────────────────
    story.append(section_title("BLACKLIST & REPUTATION CHECK"))
    bl = scan_data.get("blacklist", {})
    bl_listed = bl.get("blacklisted", False)
    bl_note = bl.get("note", "")
    bl_color = CS_RED if bl_listed else CS_GREEN
    bl_rows = [
        ["Blacklist Status", "BLACKLISTED" if bl_listed else "Clean — Not blacklisted"],
        ["Note", bl_note],
    ]
    blt = Table(bl_rows, colWidths=[W*0.30, W*0.70])
    blt.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (0,-1), CS_DARK),
        ("BACKGROUND",  (1,0), (1,-1), CS_DARKER),
        ("TEXTCOLOR",   (0,0), (0,-1), CS_BLUE),
        ("TEXTCOLOR",   (1,0), (1,-1), CS_WHITE),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("PADDING",     (0,0), (-1,-1), 9),
        ("GRID",        (0,0), (-1,-1), 0.5, CS_LINE),
        ("LINEABOVE",   (0,0), (-1,0), 2, bl_color),
    ]))
    story.append(blt)
    story.append(Spacer(1, 5*mm))

    # ── RECOMMENDATIONS ───────────────────────────────────────────────────────
    story.append(section_title("SECURITY RECOMMENDATIONS"))
    recs = []
    if not ssl_valid:
        recs.append(("CRITICAL", "Install a valid SSL certificate immediately (Let's Encrypt — free)."))
    elif isinstance(ssl_days, int) and ssl_days < 30:
        recs.append(("HIGH", f"SSL certificate expires in {ssl_days} days — renew urgently."))
    for p in ports:
        pn = p.get("port")
        if pn == 23 and p.get("state") == "open":
            recs.append(("CRITICAL", "Disable Telnet (port 23) — insecure protocol, replace with SSH."))
        if pn == 21 and p.get("state") == "open":
            recs.append(("HIGH", "Disable FTP (port 21) — use SFTP or FTPS instead."))
        if pn == 3306 and p.get("state") == "open":
            recs.append(("CRITICAL", "MySQL (port 3306) is publicly exposed — restrict via firewall immediately."))
        if pn == 5432 and p.get("state") == "open":
            recs.append(("CRITICAL", "PostgreSQL (port 5432) is publicly exposed — restrict access immediately."))
    if bl_listed:
        recs.append(("CRITICAL", "Domain is blacklisted — contact CyberShield immediately."))
    if not recs:
        recs.append(("OK", "No critical vulnerabilities detected. Maintain active monitoring."))

    rec_rows = [["Priority", "Recommendation"]]
    for level, text in recs:
        rec_rows.append([level, text])
    rct = Table(rec_rows, colWidths=[W*0.18, W*0.82])
    rec_colors = {"CRITICAL": CS_RED, "HIGH": CS_ORANGE, "OK": CS_GREEN}
    rct_style = TableStyle([
        ("BACKGROUND", (0,0), (-1,0), CS_BLUE),
        ("TEXTCOLOR",  (0,0), (-1,0), CS_WHITE),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
        ("PADDING",    (0,0), (-1,-1), 8),
        ("GRID",       (0,0), (-1,-1), 0.5, CS_LINE),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [CS_DARKER, CS_DARK]),
        ("TEXTCOLOR",  (1,1), (1,-1), CS_WHITE),
    ])
    for i, (level, _) in enumerate(recs, start=1):
        c = rec_colors.get(level, CS_WHITE)
        rct_style.add("TEXTCOLOR", (0,i), (0,i), c)
        rct_style.add("FONTNAME",  (0,i), (0,i), "Helvetica-Bold")
    rct.setStyle(rct_style)
    story.append(rct)
    story.append(Spacer(1, 8*mm))

    # ── FOOTER ────────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=CS_BLUE))
    story.append(Spacer(1, 3*mm))
    footer_data = [[
        Paragraph("CyberShield — cybersh.tech", ParagraphStyle("fl", fontSize=8, textColor=CS_GRAY)),
        Paragraph("alerts@cybersh.tech", ParagraphStyle("fm", fontSize=8, textColor=CS_GRAY, alignment=TA_CENTER)),
        Paragraph(f"Generated: {datetime.now().strftime('%d %b %Y %H:%M')}", ParagraphStyle("fr", fontSize=8, textColor=CS_GRAY, alignment=TA_RIGHT)),
    ]]
    ft = Table(footer_data, colWidths=[W*0.33, W*0.34, W*0.33])
    ft.setStyle(TableStyle([("PADDING", (0,0), (-1,-1), 0)]))
    story.append(ft)

    doc.build(story)
    print(f"[CyberShield] Report generated: {filename}")
    return filename

if __name__ == "__main__":
    result = generate_report(client_id=1)
    if result:
        print(f"[OK] PDF saved: {result}")
