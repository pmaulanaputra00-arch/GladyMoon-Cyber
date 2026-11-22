from flask import Flask, request, render_template_string, Response, session, redirect, url_for
from functools import wraps
import requests
import csv
import os
import socket
import ssl
import ipaddress
from datetime import datetime
from urllib.parse import urlparse
from io import StringIO

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-this")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True
)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function
FILE = "scan_history.csv"

HEADERS_CHECK = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy"
]


def load_history():
    if not os.path.exists(FILE):
        return []

    history = []
    with open(FILE, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Support older CSV header variants.
            values = {str(k).strip().lower(): (v or "").strip()
                      for k, v in row.items() if k is not None}
            website = (values.get("website") or values.get("domain")
                       or values.get("host") or "")
            status = values.get("status") or values.get("http status") or ""
            https = values.get("https") or "Tidak diketahui"
            scan_time = (values.get("time") or values.get("waktu")
                         or values.get("tanggal") or "")

            # Repair common legacy rows where website and status were shifted.
            if website.isdigit() and status and not status.isdigit():
                website, status = status, website
            if scan_time and scan_time.isdigit() and website and not website.isdigit():
                scan_time, website = website, scan_time

            history.append({
                "website": website,
                "status": status,
                "https": https,
                "time": scan_time
            })
    return history


def save_history(data):
    exists = os.path.exists(FILE)
    with open(FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["website", "status", "https", "time"]
        )
        if not exists or os.path.getsize(FILE) == 0:
            writer.writeheader()
        writer.writerow(data)


def check_tls(host):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                return secure_sock.version() or "Tidak diketahui"
    except Exception:
        return "Tidak tersedia"



def validate_public_host(host):
    try:
        records = socket.getaddrinfo(
            host, 443, type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise ValueError("DNS gagal menemukan domain")

    if not records:
        raise ValueError("Alamat domain tidak ditemukan")

    public_found = False

    for record in records:
        ip = ipaddress.ip_address(record[4][0])

        if ip.is_global:
            public_found = True

    if not public_found:
        raise ValueError("Domain tidak memiliki IP publik")

def scan_website(website):
    raw = website.strip()
    parsed = urlparse(raw if "://" in raw else "https://" + raw)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Gunakan alamat HTTP atau HTTPS")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Domain tidak valid")

    host = parsed.hostname
    validate_public_host(host)

    # Scanner hanya meminta halaman utama HTTPS dan tidak mengikuti redirect.
    response = requests.get(
        "https://" + host,
        timeout=10,
        allow_redirects=False,
        headers={"User-Agent": "CyberSecurityDashboard/30"}
    )

    return {
        "website": host,
        "status": response.status_code,
        "https": "Aktif",
        "tls": check_tls(host),
        "headers": {h: h in response.headers for h in HEADERS_CHECK},
        "time": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    }


HTML = """
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CYBER SECURITY | AI ROBOT v30</title>
<style>
*{box-sizing:border-box}
:root{--bg:#050d1b;--panel:#0b1b32;--blue:#19caff;--cyan:#65eaff;
--muted:#829bb8;--green:#42f5b5;--red:#ff6d85}
body{margin:0;padding:22px;background:
radial-gradient(ellipse at 75% 0%,#10345a 0%,transparent 38%),
radial-gradient(ellipse at 10% 90%,#09284b 0%,transparent 35%),var(--bg);
color:#eaf8ff;font-family:Arial,sans-serif;min-height:100vh}
body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.10;
background-image:linear-gradient(rgba(25,202,255,.2) 1px,transparent 1px),
linear-gradient(90deg,rgba(25,202,255,.2) 1px,transparent 1px);
background-size:35px 35px}
.layout{position:relative;display:flex;gap:22px;max-width:1600px;margin:auto}
.sidebar{width:245px;min-width:245px;min-height:calc(100vh - 44px);
padding:22px 17px;background:rgba(5,19,39,.96);border:1px solid #19415d;
border-radius:20px;box-shadow:0 0 30px #008cff18}
.brand{text-align:center;color:var(--cyan);font-size:19px;font-weight:900;
letter-spacing:2px;margin:8px 0 20px}
.robot{height:180px;display:flex;justify-content:center;align-items:center;
position:relative;margin-bottom:12px}
.robot-glow{position:absolute;width:140px;height:140px;border-radius:50%;
background:#008cff;filter:blur(55px);opacity:.4}
.robot-head{position:relative;width:112px;height:105px;border:3px solid #7ceaff;
border-radius:30px 30px 37px 37px;background:linear-gradient(145deg,#e8fbff,#668ba5);
box-shadow:0 0 25px #00bfff}
.robot-head:before{content:"";position:absolute;left:15px;right:15px;top:30px;
height:30px;border-radius:12px;background:#071b36;border:2px solid #36dfff;
box-shadow:0 0 15px #00cfff}
.robot-head:after{content:"●     ●";position:absolute;top:36px;left:27px;
color:#47eaff;font-size:13px;text-shadow:0 0 10px #00d9ff}
.robot-ear{position:absolute;width:13px;height:34px;top:37px;background:#19bde8;
border-radius:6px}
.robot-ear.left{left:-13px}.robot-ear.right{right:-13px}
.robot-neck{position:absolute;width:35px;height:16px;bottom:-17px;left:36px;
background:#8db6cb;border-radius:5px}
.robot-label{text-align:center;color:#61dfff;font-size:10px;letter-spacing:3px;
margin-bottom:27px}
.nav-title{color:#587d9e;font-size:10px;letter-spacing:2px;margin:22px 10px 10px}
.sidebar a{display:block;color:#a8c4dc;text-decoration:none;padding:13px;
margin:6px 0;border-radius:9px;font-size:13px;transition:.2s}
.sidebar a:hover,.sidebar a.active{color:white;background:#00aeff26;
border:1px solid #00c3ff55;box-shadow:0 0 15px #00b4ff1f}
.main{flex:1;min-width:0}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:15px;margin-bottom:22px}
h1{font-size:25px;letter-spacing:3px;margin:0;text-shadow:0 0 15px #00c3ff80}
.subtitle{color:var(--muted);font-size:11px;margin-top:8px;letter-spacing:1px}
.online{color:var(--green);border:1px solid #42f5b566;padding:10px 15px;
border-radius:30px;font-size:11px;background:#14b47814;white-space:nowrap}
.panel{background:linear-gradient(145deg,#102745ed,#07172bed);border:1px solid #19415d;
border-radius:15px;padding:19px;box-shadow:0 8px 30px #0003;margin-bottom:17px;
position:relative;overflow:hidden}
.panel:before{content:"";position:absolute;top:0;left:15px;right:15px;height:1px;
background:linear-gradient(90deg,transparent,#24d8ff,transparent)}
.panel h3{font-size:14px;letter-spacing:1px;margin:0 0 17px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.stat{background:linear-gradient(145deg,#0c314fe6,#07172ce6);border:1px solid #19415d;
border-radius:13px;padding:18px;min-width:0}
.stat-label{color:#8eabc5;font-size:11px}
.stat h2{color:var(--cyan);font-size:29px;margin:12px 0 0;text-shadow:0 0 12px #00c3ff80}
.grid{display:grid;grid-template-columns:1.5fr 1fr;gap:16px;margin-bottom:17px}
.description{color:var(--muted);font-size:12px;line-height:1.7;margin-bottom:17px}
input{width:100%;background:#07182c;border:1px solid #19516d;padding:14px;
border-radius:9px;color:white;outline:none;margin-bottom:12px}
input:focus{border-color:var(--cyan);box-shadow:0 0 13px #19caff33}
button{width:100%;border:0;border-radius:9px;padding:14px;color:#00121f;
background:linear-gradient(90deg,#17bdf5,#6beaff);font-weight:900;
letter-spacing:2px;cursor:pointer}
button:hover{box-shadow:0 0 20px #19caff70}
.warning{color:#819bb5;font-size:10px;margin-top:12px}
.donut-wrap{display:flex;justify-content:center;align-items:center;padding:8px}
.donut{width:155px;height:155px;border-radius:50%;display:grid;place-items:center;
background:conic-gradient(#17d9ff {{ success_percent }}%,#f05270 0);
box-shadow:0 0 25px #00c3ff20}
.donut-inner{width:112px;height:112px;border-radius:50%;background:#0a1b30;
display:flex;flex-direction:column;justify-content:center;align-items:center}
.donut-inner strong{font-size:25px;color:var(--cyan)}
.donut-inner span{font-size:10px;color:var(--muted)}
.legend{display:flex;justify-content:center;gap:17px;flex-wrap:wrap;
color:#a7bfd4;font-size:10px;margin-top:14px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px}
.success{color:var(--green)}.failed{color:var(--red)}
.result-panel {
    border: 1px solid #19caff55;
    box-shadow: 0 0 25px #00bfff18;
}

.result-panel h3 {
    color: #65eaff;
    text-shadow: 0 0 10px #19caff66;
}

.result-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    padding: 13px 10px;
    border-bottom: 1px solid #64b4dc24;
    font-size: 12px;
    transition: .2s;
}

.result-row:hover {
    background: #19caff0c;
}

.result-row span:first-child {
    color: #829bb8;
}

.result-row strong {
    text-align: right;
 
   overflow-wrap: anywhere;
}
.result-row span:first-child{color:#829bb8}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:500px;font-size:11px}
th{text-align:left;color:#55dfff;background:#0096dc1a}
th,td{padding:13px 10px;border-bottom:1px solid #64b4dc1f}
td{color:#b5cadd;overflow-wrap:anywhere}
.empty{text-align:center;color:#7895b1;padding:22px;font-size:12px}
.activity{color:#a9c2d9;font-size:11px;line-height:1.9}
.activity-item{border-left:2px solid #18cfff;padding-left:12px;margin:12px 0}
.footer{text-align:center;color:#496b88;font-size:10px;margin:25px 0 10px}
@media(max-width:1000px){.sidebar{width:190px;min-width:190px}
.stats{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}}
@media(max-width:650px){
body{padding:7px}
.layout{display:block}
.sidebar{width:100%;min-width:0;min-height:0;padding:8px 10px;margin-bottom:9px;border-radius:12px}
.brand{font-size:14px;letter-spacing:1.5px;margin:2px 0 5px}
.robot{height:48px;margin:0}
.robot-glow{width:55px;height:45px;filter:blur(22px)}
.robot-head{transform:scale(.40);transform-origin:center}
.robot-label{font-size:8px;letter-spacing:2px;margin:0 0 5px}
.sidebar nav{display:flex;flex-wrap:wrap;gap:4px;justify-content:center}
.nav-title{display:none}
.sidebar a{display:inline-block;margin:0;padding:7px 9px;font-size:10px;text-align:center;border-radius:7px}
.sidebar>.nav-title,.sidebar>p{display:none}
.topbar{align-items:center;margin-bottom:9px;gap:7px}
.topbar h1{font-size:16px;letter-spacing:1.5px}
.subtitle{font-size:8px;letter-spacing:.4px;margin-top:4px}
.online{font-size:8px;padding:6px 8px}
.stats{grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-bottom:9px}
.stat{padding:9px;border-radius:9px}
.stat-label{font-size:9px}
.stat h2{font-size:21px;margin-top:6px}
.grid{grid-template-columns:1fr;gap:8px;margin-bottom:8px}
.panel{padding:11px;margin-bottom:8px;border-radius:10px}
.panel h3{font-size:12px;margin-bottom:9px}
.description{font-size:10px;line-height:1.45;margin-bottom:9px}
input{padding:10px;margin-bottom:8px;font-size:12px}
button{padding:10px;font-size:11px}
.warning{font-size:9px;margin-top:7px}
.donut-wrap{padding:2px}
.donut{width:105px;height:105px}
.donut-inner{width:76px;height:76px}
.donut-inner strong{font-size:19px}
.donut-inner span{font-size:8px}
.legend{font-size:9px;margin-top:7px}
.result-row{font-size:10px;padding:7px 0}
table{min-width:440px;font-size:9px}
th,td{padding:7px 5px}
.activity-item{margin:7px 0}
.footer{margin:12px 0 5px;font-size:9px}
}
.tab-page{display:none}
.tab-page.active-page{display:block}
.tab-link{cursor:pointer}
@media(prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>
</head>
<body>
<div class="layout">

<aside class="sidebar">
    <div class="brand">⬡ CYBER SECURITY</div>
    <div class="robot">
        <div class="robot-glow"></div>
        <div class="robot-head">
            <div class="robot-ear left"></div>
            <div class="robot-ear right"></div>
            <div class="robot-neck"></div>
        </div>
    </div>
    <div class="robot-label">AI SECURITY CORE</div>
    <nav>
        <div class="nav-title">MAIN MENU</div>
        <a class="active tab-link" href="#" data-tab="dashboard">▣ Dashboard</a>
        <a class="tab-link" href="#" data-tab="scanner-page">⌕ Website Scanner</a>
        <a class="tab-link" href="#" data-tab="statistics-page">▥ Statistics</a>
        <a class="tab-link" href="#" data-tab="history-page">▤ Scan History</a>
        <div class="nav-title">SYSTEM</div>
        <a href="/download">⇩ Export Report</a>
    </nav>
    <div class="nav-title">SYSTEM STATUS</div>
    <p class="success" style="font-size:12px">● SYSTEM ONLINE</p>
    <p class="description">AI Security Core v30</p>
</aside>

<main class="main">
    <header class="topbar">
        <div>
            <h1>CYBER SECURITY</h1>
            <div class="subtitle">ADVANCED AI SECURITY DASHBOARD / VERSION 30</div>
        </div>
        <div class="online">● SYSTEM ONLINE</div>
    </header>

    <section class="tab-page active-page" id="dashboard">
      <section class="stats">
        <div class="stat"><div class="stat-label">TOTAL SCAN</div><h2>{{ total }}</h2></div>
        <div class="stat"><div class="stat-label">HTTPS SCAN</div><h2>{{ https_total }}</h2></div>
        <div class="stat"><div class="stat-label">STATUS 2XX</div><h2>{{ success_total }}</h2></div>
        <div class="stat"><div class="stat-label">FAILED / OTHER</div><h2>{{ other_total }}</h2></div>
      </section>
      <section class="panel">
        <h3>◈ RECENT ACTIVITY</h3>
        <div class="activity">
          {% for item in history[:5] %}
          <div class="activity-item">
            <strong>SCAN COMPLETED</strong><br>
            {{ item.website }}<br><small>{{ item.time }} · HTTP {{ item.status }}</small>
          </div>
          {% else %}
          <p class="empty">Belum ada aktivitas terbaru</p>
          {% endfor %}
        </div>
      </section>
    </section>

    <section class="tab-page" id="scanner-page">
        <div class="panel" id="scanner">
            <h3>⌕ WEBSITE SCANNER</h3>
            <p class="description">Masukkan domain publik milik sendiri atau yang sudah mendapat izin untuk diperiksa.</p>
            <form method="POST" action="/scan">
                <input name="website" placeholder="example.com" required>
                <button type="submit">SCAN WEBSITE</button>
            </form>
            <p class="warning">Gunakan hanya pada website yang kamu miliki atau sudah mendapat izin.</p>
        </div>
    </section>

    <section class="tab-page" id="statistics-page">
        <div class="panel" id="statistics">
            <h3>◉ SCAN STATISTICS</h3>
            <div class="donut-wrap">
                <div class="donut">
                    <div class="donut-inner">
                        <strong>{{ success_percent|round|int }}%</strong>
                        <span>SUCCESS RATE</span>
                    </div>
                </div>
            </div>
            <div class="legend">
                <span><i class="dot" style="background:#17d9ff"></i>Berhasil {{ success_total }}</span>
                <span><i class="dot" style="background:#f05270"></i>Lainnya {{ other_total }}</span>
            </div>
        </div>
    </section>

    {% if result %}
    <section class="panel result-panel">
        <h3>▣ HASIL SCAN</h3>
        <div class="result-row"><span>Website</span><strong>{{ result.website }}</strong></div>
        <div class="result-row"><span>Status HTTP</span><strong>{{ result.status }}</strong></div>
        <div class="result-row"><span>HTTPS</span><strong class="success">{{ result.https }}</strong></div>
        <div class="result-row"><span>TLS</span><strong>{{ result.tls }}</strong></div>
        <div class="result-row"><span>Waktu</span><strong>{{ result.time }}</strong></div>
        <h3 style="margin-top:20px">SECURITY HEADERS</h3>
        {% for header, active in result.headers.items() %}
        <div class="result-row">
            <span>{{ header }}</span>
            <strong class="{{ 'success' if active else 'failed' }}">
                {{ 'AKTIF' if active else 'TIDAK DITEMUKAN' }}
            </strong>
        </div>
        {% endfor %}
    </section>
    {% endif %}

    <section class="tab-page" id="history-page">
        <div class="panel" id="history">
            <h3>▤ SCAN HISTORY</h3>
            <div class="table-wrap">
                <table>
                    <tr><th>WEBSITE</th><th>STATUS</th><th>HTTPS</th><th>WAKTU</th></tr>
                    {% for item in history[:8] %}
                    <tr>
                        <td>{{ item.website }}</td>
                        <td>{{ item.status }}</td>
                        <td>{{ item.https }}</td>
                        <td>{{ item.time }}</td>
                    </tr>
                    {% else %}
                    <tr><td colspan="4" class="empty">Belum ada riwayat scan</td></tr>
                    {% endfor %}
                </table>
            </div>
        </div>
    </section>

    <div class="footer">CYBER SECURITY AI DASHBOARD · VERSION 30</div>
</main>
</div>

<script>
document.querySelectorAll(".tab-link").forEach(function(link) {
  link.addEventListener("click", function(event) {
    event.preventDefault();
    const target = link.dataset.tab;
    document.querySelectorAll(".tab-page").forEach(function(page) {
      page.classList.toggle("active-page", page.id === target);
    });
    document.querySelectorAll(".tab-link").forEach(function(item) {
      item.classList.toggle("active", item === link);
    });
    window.scrollTo({top: 0, behavior: "smooth"});
  });
});
</script>
</body>
</html>
"""


def dashboard_data(result=None):
    history = load_history()
    total = len(history)
    https_total = sum(1 for x in history if x["https"] == "Aktif")
    success_total = sum(1 for x in history if str(x["status"]).startswith("2"))
    other_total = total - success_total

    return render_template_string(
        HTML,
        history=history[::-1],
        total=total,
        https_total=https_total,
        success_total=success_total,
        other_total=other_total,
        success_percent=success_total / total * 100 if total else 0,
        result=result
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    password = os.environ.get("DASHBOARD_PASSWORD")

    if not password:
        return "Login belum dikonfigurasi di Render.", 503

    if request.method == "POST":
        entered = request.form.get("password", "")

        import secrets
        if secrets.compare_digest(entered, password):
            session["logged_in"] = True
            return redirect(url_for("dashboard"))

        return "Password salah. <a href='/login'>Coba lagi</a>", 401

    return """
    <h2>GladyMoon-Cyber</h2>
    <h3>Login Dashboard</h3>
    <form method="POST">
        <input type="password" name="password"
               placeholder="Masukkan password" required>
        <button type="submit">LOGIN</button>
    </form>
    """


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    return dashboard_data()

@app.route("/scan", methods=["POST"])
@login_required
def scan():
    website = request.form.get("website", "").strip()

    try:
        result = scan_website(website)
        save_history({
            "website": result["website"],
            "status": result["status"],
            "https": result["https"],
            "time": result["time"]
        })
        return dashboard_data(result)

    except (requests.RequestException, ValueError, OSError) as error:
        return (
            "<h2>Scan tidak berhasil</h2>"
            f"<p>{str(error)}</p>"
            '<a href="/">Kembali ke Dashboard</a>',
            400
        )


@app.route("/download")
@login_required
def download():
    history = load_history()
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["website", "status", "https", "time"]
    )
    writer.writeheader()
    writer.writerows(history)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=scan_report.csv"
        }
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
