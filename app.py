from flask import Flask, render_template, request, redirect, url_for, send_file, session
import io, json, sqlite3, os, uuid
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 Table, TableStyle, HRFlowable)

app = Flask(__name__)
app.secret_key = "logsentinel-private-2026-xK9mP"
DB_PATH = os.path.join(os.path.dirname(__file__), "history.db")

# ─────────────────────────────────────────────────────────────────────────────
# THRESHOLDS
# Badge scale (per-user request count):
#   1  – 4   →  SAFE
#   5  – 10  →  LOW RISK
#   11 – 15  →  MEDIUM RISK
#   16+      →  HIGH RISK
# Risk score:
#   >= 38  →  CRITICAL
#   >= 22  →  WARNING
#   <  22  →  SAFE
# ─────────────────────────────────────────────────────────────────────────────
HIGH_RISK_REQS   = 15
MEDIUM_RISK_REQS = 10
LOW_RISK_REQS    = 4
SCORE_CRITICAL   = 38
SCORE_WARNING    = 22

def classify_user(req_count):
    """Return (label, colour_key) for a user based on request count."""
    if   req_count > HIGH_RISK_REQS:   return "HIGH RISK",   "high"
    elif req_count > MEDIUM_RISK_REQS: return "MEDIUM RISK", "medium"
    elif req_count > LOW_RISK_REQS:    return "LOW RISK",    "low"
    else:                               return "SAFE",        "safe"

# ─────────────────────────────────────────────────────────────────────────────
# SESSION HELPER
# Every browser gets a unique session_id on first visit.
# All DB reads/writes are filtered by this ID → complete privacy isolation.
# ─────────────────────────────────────────────────────────────────────────────
def get_session_id():
    """Return the current browser's unique session ID, creating one if needed."""
    if "session_id" not in session:
        session["session_id"] = str(uuid.uuid4())
    return session["session_id"]

# ─────────────────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        # Create table with session_id column for privacy isolation
        conn.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id       TEXT NOT NULL DEFAULT '',
                filename         TEXT NOT NULL,
                analyzed_at      TEXT NOT NULL,
                most_active_user TEXT,
                most_active_ip   TEXT,
                error_count      INTEGER DEFAULT 0,
                suspicious_count INTEGER DEFAULT 0,
                total_requests   INTEGER DEFAULT 0,
                chart_users_json TEXT,
                chart_ips_json   TEXT,
                suspicious_json  TEXT
            )
        """)
        # Add session_id column to existing DB if upgrading from old version
        try:
            conn.execute("ALTER TABLE history ADD COLUMN session_id TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass  # column already exists — fine
        conn.execute("CREATE INDEX IF NOT EXISTS idx_session ON history(session_id)")
        conn.commit()

init_db()

# ─────────────────────────────────────────────────────────────────────────────
# LOG ANALYSER
# ─────────────────────────────────────────────────────────────────────────────
def analyze_logs(file):
    user_count  = {}
    ip_count    = {}
    error_count = 0
    total_lines = 0

    for line in file.readlines():
        try:
            parts = line.decode("utf-8", errors="ignore").strip().split(" - ")
            if len(parts) < 3:
                continue
            ip, user, status = parts[0], parts[1], int(parts[2])
        except (ValueError, IndexError):
            continue
        total_lines += 1
        user_count[user] = user_count.get(user, 0) + 1
        ip_count[ip]     = ip_count.get(ip, 0) + 1
        if status >= 400:
            error_count += 1

    if not user_count:
        return None

    most_active_user = max(user_count, key=user_count.get)
    most_active_ip   = max(ip_count,   key=ip_count.get)

    all_users   = list(user_count.keys())
    risky_users = [u for u, c in user_count.items() if c > LOW_RISK_REQS]

    top_users = dict(sorted(user_count.items(), key=lambda x: x[1], reverse=True)[:10])
    top_ips   = dict(sorted(ip_count.items(),   key=lambda x: x[1], reverse=True)[:10])

    # Risk score
    score = 0
    if total_lines > 0:
        score += min(35, int((error_count / total_lines) * 140))
    if user_count:
        max_reqs = max(user_count.values())
        if   max_reqs > HIGH_RISK_REQS:   score += 35
        elif max_reqs > MEDIUM_RISK_REQS: score += 20
        elif max_reqs > LOW_RISK_REQS:    score += 10
    score += min(20, len(risky_users) * 5)
    if total_lines > 1000: score += 5
    if total_lines > 5000: score += 5
    score = min(100, score)

    if   score >= SCORE_CRITICAL: risk_label = "CRITICAL"
    elif score >= SCORE_WARNING:  risk_label = "WARNING"
    else:                          risk_label = "SAFE"

    return {
        "most_active_user": most_active_user,
        "most_active_ip":   most_active_ip,
        "error_count":      error_count,
        "total_requests":   total_lines,
        "all_users":        all_users,
        "risky_users":      risky_users,
        "user_count":       user_count,
        "ip_count":         ip_count,
        "chart_users":      top_users,
        "chart_ips":        top_ips,
        "risk_score":       score,
        "risk_label":       risk_label,
    }

# ─────────────────────────────────────────────────────────────────────────────
# PDF GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
def generate_pdf(row):
    buffer  = io.BytesIO()
    W, H    = A4
    CONTENT = W - 36 * mm

    NAVY     = colors.HexColor("#1B3A5C")
    BLUE     = colors.HexColor("#2563EB")
    SLATE    = colors.HexColor("#475569")
    BORDER   = colors.HexColor("#CBD5E1")
    BG_ROW   = colors.HexColor("#F8FAFC")
    WHITE    = colors.white
    PAGE_BG  = colors.HexColor("#F1F5F9")
    RED_BG   = colors.HexColor("#FEF2F2")
    RED_TEXT = colors.HexColor("#B91C1C")
    RED_BRD  = colors.HexColor("#FECACA")
    ORG_BG   = colors.HexColor("#FFF7ED")
    ORG_TEXT = colors.HexColor("#EA580C")
    ORG_BRD  = colors.HexColor("#FED7AA")
    YLW_BG   = colors.HexColor("#FEFCE8")
    YLW_TEXT = colors.HexColor("#CA8A04")
    YLW_BRD  = colors.HexColor("#FEF08A")
    GRN_BG   = colors.HexColor("#F0FDF4")
    GRN_TEXT = colors.HexColor("#16A34A")
    GRN_BRD  = colors.HexColor("#86EFAC")

    RISK_COLOURS = {
        "HIGH RISK":   (RED_BG,  RED_TEXT,  RED_BRD),
        "MEDIUM RISK": (ORG_BG,  ORG_TEXT,  ORG_BRD),
        "LOW RISK":    (YLW_BG,  YLW_TEXT,  YLW_BRD),
        "SAFE":        (GRN_BG,  GRN_TEXT,  GRN_BRD),
    }

    def ps(name, **kw):
        p = ParagraphStyle(name)
        for k, v in kw.items(): setattr(p, k, v)
        return p

    s_tag = ps("tag", fontName="Helvetica",      fontSize=8,   textColor=BLUE,  leading=11)
    s_ttl = ps("ttl", fontName="Helvetica-Bold", fontSize=20,  textColor=NAVY,  leading=26)
    s_sub = ps("sub", fontName="Helvetica",      fontSize=9,   textColor=SLATE, leading=13)
    s_brd = ps("brd", fontName="Helvetica-Bold", fontSize=13,  textColor=BLUE,  leading=16, alignment=TA_RIGHT)
    s_sec = ps("sec", fontName="Helvetica-Bold", fontSize=8,   textColor=SLATE, leading=11)
    s_lbl = ps("lbl", fontName="Helvetica",      fontSize=8,   textColor=SLATE, leading=11)
    s_val = ps("val", fontName="Helvetica-Bold", fontSize=11,  textColor=NAVY,  leading=14)
    s_non = ps("non", fontName="Helvetica",      fontSize=10,  textColor=SLATE, leading=14, alignment=TA_CENTER)
    s_ftr = ps("ftr", fontName="Helvetica",      fontSize=7.5, textColor=SLATE, leading=10, alignment=TA_CENTER)

    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(PAGE_BG)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        canvas.restoreState()

    now   = row["analyzed_at"]
    story = []

    # Header
    left_w  = 124 * mm
    right_w = CONTENT - left_w
    inner = Table(
        [[Paragraph("LOG ANALYSIS REPORT", s_tag)],
         [Paragraph("Security Intelligence Summary", s_ttl)],
         [Paragraph(f"Generated  {now}", s_sub)]],
        colWidths=[left_w - 28]
    )
    inner.setStyle(TableStyle([
        ("LEFTPADDING",(0,0),(-1,-1),0),("RIGHTPADDING",(0,0),(-1,-1),0),
        ("TOPPADDING",(0,0),(-1,-1),2),("BOTTOMPADDING",(0,0),(-1,-1),2),
    ]))
    hdr = Table([[inner, Paragraph("LogSentinel", s_brd)]], colWidths=[left_w, right_w])
    hdr.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),WHITE),("BOX",(0,0),(-1,-1),0.5,BORDER),
        ("LEFTPADDING",(0,0),(-1,-1),14),("RIGHTPADDING",(0,0),(-1,-1),14),
        ("TOPPADDING",(0,0),(-1,-1),14),("BOTTOMPADDING",(0,0),(-1,-1),14),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
    ]))
    story.append(hdr)
    story.append(Spacer(1, 5*mm))
    story.append(HRFlowable(width="100%", thickness=2, color=BLUE, spaceAfter=5*mm))

    # Key metrics
    story.append(Paragraph("KEY METRICS", s_sec))
    story.append(Spacer(1, 2*mm))
    col_a, col_b = 90*mm, CONTENT - 90*mm
    metrics = [
        ("File Analysed",    row["filename"]),
        ("Most Active User", row["most_active_user"] or "-"),
        ("Most Active IP",   row["most_active_ip"]   or "-"),
        ("Total Requests",   str(row["total_requests"])),
        ("Total Errors",     str(row["error_count"])),
        ("Risky Users",      str(row["suspicious_count"])),
    ]
    m_rows = [[Paragraph(l, s_lbl), Paragraph(v, s_val)] for l, v in metrics]
    m_st = [
        ("BOX",(0,0),(-1,-1),0.5,BORDER),("LINEBELOW",(0,0),(-1,-2),0.5,BORDER),
        ("LEFTPADDING",(0,0),(-1,-1),12),("RIGHTPADDING",(0,0),(-1,-1),12),
        ("TOPPADDING",(0,0),(-1,-1),10),("BOTTOMPADDING",(0,0),(-1,-1),10),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
    ]
    for i in range(len(m_rows)):
        m_st.append(("BACKGROUND",(0,i),(-1,i), WHITE if i%2==0 else BG_ROW))
    m_tbl = Table(m_rows, colWidths=[col_a, col_b])
    m_tbl.setStyle(TableStyle(m_st))
    story.append(m_tbl)
    story.append(Spacer(1, 6*mm))

    # User activity table with correct per-user risk labels
    story.append(Paragraph("USER ACTIVITY", s_sec))
    story.append(Spacer(1, 2*mm))
    all_users_data = json.loads(row["chart_users_json"] or "{}")

    if all_users_data:
        col_user  = 70*mm
        col_reqs  = 30*mm
        col_label = CONTENT - col_user - col_reqs
        u_rows = []
        for username, req_count in all_users_data.items():
            risk_lbl, _ = classify_user(req_count)
            bg, txt, brd = RISK_COLOURS[risk_lbl]
            s_risk = ps(f"r_{username}", fontName="Helvetica-Bold", fontSize=7,
                        textColor=txt, leading=10, alignment=TA_RIGHT)
            s_name = ps(f"n_{username}", fontName="Helvetica",      fontSize=10,
                        textColor=NAVY, leading=13)
            s_reqs = ps(f"q_{username}", fontName="Helvetica",      fontSize=10,
                        textColor=SLATE, leading=13)
            u_rows.append([
                Paragraph(str(username), s_name),
                Paragraph(f"{req_count} reqs", s_reqs),
                Paragraph(risk_lbl, s_risk),
            ])
        u_st = [
            ("BOX",(0,0),(-1,-1),0.5,BORDER),("LINEBELOW",(0,0),(-1,-2),0.5,BORDER),
            ("LEFTPADDING",(0,0),(-1,-1),12),("RIGHTPADDING",(0,0),(-1,-1),10),
            ("TOPPADDING",(0,0),(-1,-1),9),("BOTTOMPADDING",(0,0),(-1,-1),9),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ALIGN",(2,0),(-1,-1),"RIGHT"),
        ]
        for i in range(len(u_rows)):
            u_st.append(("BACKGROUND",(0,i),(-1,i), WHITE if i%2==0 else BG_ROW))
        u_tbl = Table(u_rows, colWidths=[col_user, col_reqs, col_label])
        u_tbl.setStyle(TableStyle(u_st))
        story.append(u_tbl)
    else:
        ok = Table([[Paragraph("No user data available.", s_non)]], colWidths=[CONTENT])
        ok.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),GRN_BG),("BOX",(0,0),(-1,-1),0.5,GRN_BRD),
            ("TOPPADDING",(0,0),(-1,-1),14),("BOTTOMPADDING",(0,0),(-1,-1),14),
        ]))
        story.append(ok)

    story.append(Spacer(1, 10*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=4*mm))
    story.append(Paragraph("LogSentinel  .  " + now + "  .  Confidential", s_ftr))

    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=16*mm, bottomMargin=16*mm)
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    buffer.seek(0)
    return buffer

# ─────────────────────────────────────────────────────────────────────────────
# ROUTES  — every DB query filtered by session_id
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
def root():
    get_session_id()   # ensure session created on very first visit
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    sid = get_session_id()
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM history WHERE session_id=? ORDER BY id DESC LIMIT 50",
            (sid,)
        ).fetchall()
    total_logs        = len(rows)
    total_errors      = sum(r["error_count"] for r in rows)
    total_suspicious  = sum(r["suspicious_count"] for r in rows)
    recent            = list(reversed(rows[:8]))
    chart_labels      = json.dumps([
        r["filename"][:14] + "..." if len(r["filename"]) > 14 else r["filename"]
        for r in recent
    ])
    chart_errors_dash = json.dumps([r["error_count"]    for r in recent])
    chart_reqs_dash   = json.dumps([r["total_requests"] for r in recent])
    return render_template("dashboard.html",
                           active_page="dashboard",
                           total_logs=total_logs,
                           total_errors=total_errors,
                           total_suspicious=total_suspicious,
                           chart_labels=chart_labels,
                           chart_errors_dash=chart_errors_dash,
                           chart_reqs_dash=chart_reqs_dash,
                           recent_rows=rows[:5])

@app.route("/upload", methods=["GET", "POST"])
def upload():
    sid              = get_session_id()
    result           = None
    filename         = None
    error            = None
    chart_users_json = "null"
    chart_ips_json   = "null"

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            error = "Please select a valid log file."
        else:
            result = analyze_logs(file)
            if result is None:
                error = ("Could not parse the log file. "
                         "Each line must follow:  IP - USER - STATUS_CODE")
            else:
                filename         = file.filename
                chart_users_json = json.dumps(result["chart_users"])
                chart_ips_json   = json.dumps(result["chart_ips"])
                with get_db() as conn:
                    conn.execute("""
                        INSERT INTO history
                          (session_id, filename, analyzed_at,
                           most_active_user, most_active_ip,
                           error_count, suspicious_count, total_requests,
                           chart_users_json, chart_ips_json, suspicious_json)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        sid,
                        filename,
                        datetime.now().strftime("%d %b %Y  %H:%M"),
                        result["most_active_user"],
                        result["most_active_ip"],
                        result["error_count"],
                        len(result["risky_users"]),
                        result["total_requests"],
                        json.dumps(result["chart_users"]),
                        json.dumps(result["chart_ips"]),
                        json.dumps(result["risky_users"]),
                    ))
                    conn.commit()

    return render_template("upload.html",
                           active_page="upload",
                           result=result,
                           filename=filename,
                           error=error,
                           chart_users_json=chart_users_json,
                           chart_ips_json=chart_ips_json,
                           risk_score=result["risk_score"] if result else None,
                           risk_label=result["risk_label"] if result else None,
                           high_risk_reqs=HIGH_RISK_REQS,
                           medium_risk_reqs=MEDIUM_RISK_REQS,
                           low_risk_reqs=LOW_RISK_REQS,
                           score_critical=SCORE_CRITICAL,
                           score_warning=SCORE_WARNING)

@app.route("/history")
def history():
    sid = get_session_id()
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM history WHERE session_id=? ORDER BY id DESC",
            (sid,)
        ).fetchall()
    return render_template("history.html", active_page="history", rows=rows)

@app.route("/download/<int:report_id>")
def download(report_id):
    sid = get_session_id()
    with get_db() as conn:
        # Only allow download if this report belongs to this session
        row = conn.execute(
            "SELECT * FROM history WHERE id=? AND session_id=?",
            (report_id, sid)
        ).fetchone()
    if row is None:
        return redirect(url_for("history"))
    pdf      = generate_pdf(dict(row))
    safename = row["filename"].rsplit(".", 1)[0] + "_report.pdf"
    return send_file(pdf, mimetype="application/pdf",
                     as_attachment=True, download_name=safename)

@app.route("/clear-history", methods=["POST"])
def clear_history():
    sid = get_session_id()
    with get_db() as conn:
        # Only clears THIS user's history, not everyone's
        conn.execute("DELETE FROM history WHERE session_id=?", (sid,))
        conn.commit()
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(debug=True)