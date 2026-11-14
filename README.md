# Mediflow-Sentinel
AI-Powered Smart Emergency Response System - Smart Emergency Response &amp; Healthcare Management System
```python
# backend/main.py
"""Mediflow Sentinel - FastAPI backend (SQLite). Run: uvicorn main:app --reload"""
import hashlib, json, math, random, secrets, sqlite3, time
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE = Path(__file__).parent
DB = BASE / "mediflow.db"
STAGES = ["created", "acknowledged", "dispatched", "picked_up", "hospital_reached"]
TRAVEL = 60          # demo: seconds each ambulance leg takes
DEMO_MINUTES = 8     # demo: a full leg is shown as ~8 minutes
app = FastAPI(title="Mediflow Sentinel API")

# ---------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, pw TEXT, salt TEXT,
  role TEXT, phone TEXT, age INTEGER, blood_group TEXT, allergies TEXT, history TEXT, emergency_contact TEXT,
  linked_patient_id INTEGER, hospital_id INTEGER);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER);
CREATE TABLE IF NOT EXISTS ambulances(id INTEGER PRIMARY KEY, code TEXT, driver TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS hospitals(id INTEGER PRIMARY KEY, name TEXT, beds_total INTEGER, beds_free INTEGER,
  icu_free INTEGER, readiness TEXT);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, patient_id INTEGER, created_by INTEGER, lat REAL, lng REAL,
  located INTEGER, description TEXT, priority TEXT, score INTEGER, reasons TEXT, stage TEXT, times TEXT,
  ambulance_id INTEGER, hospital_id INTEGER, responder_id INTEGER, handoff TEXT,
  amb_lat REAL, amb_lng REAL, hosp_lat REAL, hosp_lng REAL);
"""

def q(sql, args=(), one=False):
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    rows = c.execute(sql, args).fetchall(); c.close()
    if one:
        return dict(rows[0]) if rows else None
    return [dict(r) for r in rows]

def ex(sql, args=()):
    c = sqlite3.connect(DB); cur = c.execute(sql, args); c.commit()
    i = cur.lastrowid; c.close(); return i

def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()

def add_user(name, email, pw, role, **kw):
    salt = secrets.token_hex(8)
    return ex("INSERT INTO users(name,email,pw,salt,role,phone,age,blood_group,allergies,history,emergency_contact,"
              "linked_patient_id,hospital_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
              (name, email.lower(), hash_pw(pw, salt), salt, role, kw.get("phone"), kw.get("age"),
               kw.get("blood_group"), kw.get("allergies"), kw.get("history"), kw.get("emergency_contact"),
               kw.get("linked_patient_id"), kw.get("hospital_id")))

def init_db():
    c = sqlite3.connect(DB); c.executescript(SCHEMA); c.commit()
    seeded = c.execute("SELECT 1 FROM users").fetchone(); c.close()
    if seeded:
        return
    for n, tot, free, icu in [("City General Hospital", 60, 22, 4), ("Sunrise Medical Centre", 40, 9, 2),
                              ("Lakeview Trauma Hospital", 80, 31, 6)]:
        ex("INSERT INTO hospitals(name,beds_total,beds_free,icu_free,readiness) VALUES(?,?,?,?,'Ready')", (n, tot, free, icu))
    for code, drv in [("AMB-101", "Ravi Kumar"), ("AMB-102", "Anita Rao"), ("AMB-103", "Suresh P"), ("AMB-104", "Meera N")]:
        ex("INSERT INTO ambulances(code,driver,status) VALUES(?,?,'Available')", (code, drv))
    pid = add_user("Demo Patient", "patient@demo.com", "demo123", "patient", phone="9000000001", age=58,
                   blood_group="B+", allergies="Penicillin", history="Type 2 diabetes, hypertension",
                   emergency_contact="9000000002")
    add_user("Demo Caregiver", "caregiver@demo.com", "demo123", "caregiver", phone="9000000002", linked_patient_id=pid)
    add_user("Demo Responder", "responder@demo.com", "demo123", "responder", phone="9000000003")
    add_user("Lakeview Trauma Desk", "hospital@demo.com", "demo123", "hospital", hospital_id=3)
    add_user("Admin", "admin@demo.com", "demo123", "admin")

init_db()

# ---------------------------------------------------------------- auth
def current(authorization: Optional[str] = Header(None)):
    token = (authorization or "").replace("Bearer ", "")
    u = q("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?", (token,), one=True)
    if not u:
        raise HTTPException(401, "Please sign in again.")
    return u

def need(u, *roles):
    if u["role"] not in roles:
        raise HTTPException(403, "Your role cannot do this.")

def public(u):
    keys = ["id", "name", "email", "role", "phone", "age", "blood_group", "allergies", "history",
            "emergency_contact", "linked_patient_id", "hospital_id"]
    out = {k: u[k] for k in keys}
    if u["role"] == "caregiver" and u["linked_patient_id"]:
        p = q("SELECT name FROM users WHERE id=?", (u["linked_patient_id"],), one=True)
        out["linked_patient_name"] = p["name"] if p else None
    return out

class Register(BaseModel):
    name: str; email: str; password: str; role: str
    phone: Optional[str] = None
    patient_email: Optional[str] = None
    hospital_id: Optional[int] = None

class Login(BaseModel):
    email: str; password: str

class Profile(BaseModel):
    name: str; phone: Optional[str] = None; age: Optional[int] = None; blood_group: Optional[str] = None
    allergies: Optional[str] = None; history: Optional[str] = None; emergency_contact: Optional[str] = None

class SOS(BaseModel):
    lat: float; lng: float; located: bool = True
    symptoms: list[str] = []; notes: str = ""

class StageIn(BaseModel):
    stage: str

class ValueIn(BaseModel):
    value: str

class HospitalIn(BaseModel):
    readiness: Optional[str] = None; beds_free: Optional[int] = None; icu_free: Optional[int] = None

def session_for(uid):
    t = secrets.token_urlsafe(24); ex("INSERT INTO sessions VALUES(?,?)", (t, uid)); return t

@app.post("/api/register")
def register(b: Register):
    if b.role not in ("patient", "caregiver", "responder", "hospital"):
        raise HTTPException(400, "Choose a valid role.")
    if len(b.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters.")
    if q("SELECT 1 FROM users WHERE email=?", (b.email.lower(),), one=True):
        raise HTTPException(400, "That email is already registered.")
    link = None
    if b.role == "caregiver" and b.patient_email:
        p = q("SELECT id FROM users WHERE email=? AND role='patient'", (b.patient_email.lower(),), one=True)
        if not p:
            raise HTTPException(400, "No patient is registered with that email.")
        link = p["id"]
    if b.role == "hospital" and not b.hospital_id:
        raise HTTPException(400, "Select your hospital.")
    uid = add_user(b.name, b.email, b.password, b.role, phone=b.phone, linked_patient_id=link,
                   hospital_id=b.hospital_id if b.role == "hospital" else None)
    return {"token": session_for(uid)}

@app.post("/api/login")
def login(b: Login):
    u = q("SELECT * FROM users WHERE email=?", (b.email.lower(),), one=True)
    if not u or hash_pw(b.password, u["salt"]) != u["pw"]:
        raise HTTPException(401, "Email or password is incorrect.")
    return {"token": session_for(u["id"])}

@app.get("/api/me")
def me(u=Depends(current)):
    return public(u)

@app.put("/api/profile")
def profile(b: Profile, u=Depends(current)):
    ex("UPDATE users SET name=?,phone=?,age=?,blood_group=?,allergies=?,history=?,emergency_contact=? WHERE id=?",
       (b.name, b.phone, b.age, b.blood_group, b.allergies, b.history, b.emergency_contact, u["id"]))
    return public(q("SELECT * FROM users WHERE id=?", (u["id"],), one=True))

@app.get("/api/hospitals")
def hospitals():
    return q("SELECT * FROM hospitals")

# ---------------------------------------------------------------- AI-assisted triage
# Rule-based scoring engine: keyword severity + age/risk modifiers. It suggests URGENCY only; it never diagnoses.
RULES = [
    (100, ["unconscious", "not breathing", "no pulse", "cardiac", "severe bleeding", "choking", "unresponsive",
           "seizure", "stroke", "overdose"]),
    (75, ["chest pain", "breathing", "breath", "head injury", "accident", "burn", "heavy bleeding", "fracture",
          "allergic", "fainted", "pregnan"]),
    (45, ["fever", "vomit", "dizz", "fall", "pain", "cut", "bleeding"]),
]
DISCLAIMER = "Suggested urgency only. This is not a medical diagnosis. A trained responder makes the final call."

def triage(symptoms, notes, patient):
    text = (" ".join(symptoms) + " " + notes).lower().strip()
    score, reasons = 0, []
    for weight, words in RULES:
        hit = [w for w in words if w in text]
        if hit:
            score = max(score, weight); reasons.append(f"Reported: {', '.join(hit)}")
    if not text:
        score, reasons = 70, ["No details given. Treated as urgent until a responder confirms."]
    elif score == 0:
        score, reasons = 30, ["No high-risk signs reported."]
    age = (patient or {}).get("age") or 0
    if age and (age >= 65 or age <= 5) and score >= 45:
        score += 10; reasons.append("Age group at higher risk")
    hist = ((patient or {}).get("history") or "").lower()
    if any(k in hist for k in ("heart", "asthma", "diabet", "stroke")) and score >= 45:
        score += 5; reasons.append("Existing condition on health profile")
    score = min(score, 100)
    level = "Critical" if score >= 90 else "High" if score >= 65 else "Medium" if score >= 40 else "Low"
    return {"priority": level, "score": score, "reasons": reasons}

# ---------------------------------------------------------------- simulation helpers
def offset(lat, lng, km, ang):
    d = km / 111.0
    return lat + d * math.cos(ang), lng + d * math.sin(ang) / max(0.2, math.cos(math.radians(lat)))

def lerp(a, b, f):
    return (a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f)

def simulate(a):
    """Ambulance position + ETA are computed from stage timestamps (demo data, no real GPS feed)."""
    t = json.loads(a["times"]); now = time.time(); st = a["stage"]
    S, P, H = (a["amb_lat"], a["amb_lng"]), (a["lat"], a["lng"]), (a["hosp_lat"], a["hosp_lng"])
    if st in ("created", "acknowledged"):
        return S, None, "Waiting for dispatch"
    if st == "dispatched":
        f = min(1, (now - t["dispatched"]) / TRAVEL)
        return lerp(S, P, f), math.ceil((1 - f) * DEMO_MINUTES), ("Ambulance has arrived" if f >= 1 else "Ambulance on the way")
    if st == "picked_up":
        f = min(1, (now - t["picked_up"]) / TRAVEL)
        return lerp(P, H, f), math.ceil((1 - f) * DEMO_MINUTES), ("Arriving at hospital" if f >= 1 else "Heading to hospital")
    return H, 0, "Patient handed over at hospital"

def alert_out(a):
    pos, eta, label = simulate(a)
    pat = q("SELECT name,age,blood_group,allergies,history,emergency_contact,phone FROM users WHERE id=?",
            (a["patient_id"],), one=True) or {}
    amb = q("SELECT code,driver,status FROM ambulances WHERE id=?", (a["ambulance_id"],), one=True)
    hos = q("SELECT name,readiness FROM hospitals WHERE id=?", (a["hospital_id"],), one=True)
    return {"id": a["id"], "stage": a["stage"], "priority": a["priority"], "score": a["score"],
            "reasons": json.loads(a["reasons"]), "description": a["description"], "located": bool(a["located"]),
            "lat": a["lat"], "lng": a["lng"], "times": json.loads(a["times"]), "handoff": a["handoff"],
            "patient": pat, "ambulance": amb, "hospital": hos, "hospital_id": a["hospital_id"],
            "amb_pos": pos, "hosp_pos": (a["hosp_lat"], a["hosp_lng"]), "eta_min": eta, "status_label": label,
            "disclaimer": DISCLAIMER}

# ---------------------------------------------------------------- alerts
@app.post("/api/sos")
def create_sos(b: SOS, u=Depends(current)):
    need(u, "patient", "caregiver")
    pid = u["id"] if u["role"] == "patient" else (u["linked_patient_id"] or u["id"])
    patient = q("SELECT * FROM users WHERE id=?", (pid,), one=True)
    if q("SELECT 1 FROM alerts WHERE patient_id=? AND stage!='hospital_reached'", (pid,), one=True):
        raise HTTPException(400, "An emergency is already active for this patient.")
    tri = triage(b.symptoms, b.notes, patient)
    desc = ", ".join(b.symptoms + ([b.notes] if b.notes.strip() else [])) or "No details given"
    hs = q("SELECT * FROM hospitals WHERE readiness!='Diverted' ORDER BY beds_free DESC") or q("SELECT * FROM hospitals")
    if tri["priority"] in ("Critical", "High"):
        hs = [h for h in hs if h["icu_free"] > 0] or hs
    amb = (q("SELECT * FROM ambulances WHERE status='Available'") or q("SELECT * FROM ambulances"))[0]
    al, ag = offset(b.lat, b.lng, 3.2, random.uniform(0, 6.28))
    hl, hg = offset(b.lat, b.lng, 4.5, random.uniform(0, 6.28))
    aid = ex("INSERT INTO alerts(patient_id,created_by,lat,lng,located,description,priority,score,reasons,stage,times,"
             "ambulance_id,hospital_id,handoff,amb_lat,amb_lng,hosp_lat,hosp_lng) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
             (pid, u["id"], b.lat, b.lng, int(b.located), desc, tri["priority"], tri["score"], json.dumps(tri["reasons"]),
              "created", json.dumps({"created": time.time()}), amb["id"], hs[0]["id"], "Awaiting", al, ag, hl, hg))
    ex("UPDATE ambulances SET status='Assigned' WHERE id=?", (amb["id"],))
    return alert_out(q("SELECT * FROM alerts WHERE id=?", (aid,), one=True))

@app.get("/api/alerts")
def list_alerts(u=Depends(current)):
    r = u["role"]
    if r == "patient":
        rows = q("SELECT * FROM alerts WHERE patient_id=? ORDER BY id DESC LIMIT 50", (u["id"],))
    elif r == "caregiver":
        rows = q("SELECT * FROM alerts WHERE patient_id IN (?,?) ORDER BY id DESC LIMIT 50", (u["id"], u["linked_patient_id"] or 0))
    elif r == "hospital":
        rows = q("SELECT * FROM alerts WHERE hospital_id=? ORDER BY id DESC LIMIT 50", (u["hospital_id"],))
    else:
        rows = q("SELECT * FROM alerts ORDER BY id DESC LIMIT 100")
    return [alert_out(a) for a in rows]

@app.post("/api/alerts/{aid}/stage")
def set_stage(aid: int, b: StageIn, u=Depends(current)):
    need(u, "responder", "admin")
    a = q("SELECT * FROM alerts WHERE id=?", (aid,), one=True)
    if not a:
        raise HTTPException(404, "Alert not found.")
    if b.stage not in STAGES or STAGES.index(b.stage) != STAGES.index(a["stage"]) + 1:
        raise HTTPException(400, "Stages must be completed in order.")
    t = json.loads(a["times"]); t[b.stage] = time.time()
    ex("UPDATE alerts SET stage=?, times=?, responder_id=COALESCE(responder_id,?) WHERE id=?",
       (b.stage, json.dumps(t), u["id"], aid))
    amb_status = {"acknowledged": "Assigned", "dispatched": "En Route", "picked_up": "Transporting",
                  "hospital_reached": "Available"}[b.stage]
    ex("UPDATE ambulances SET status=? WHERE id=?", (amb_status, a["ambulance_id"]))
    return alert_out(q("SELECT * FROM alerts WHERE id=?", (aid,), one=True))

@app.post("/api/alerts/{aid}/handoff")
def set_handoff(aid: int, b: ValueIn, u=Depends(current)):
    need(u, "hospital", "admin")
    a = q("SELECT * FROM alerts WHERE id=?", (aid,), one=True)
    if not a or (u["role"] == "hospital" and a["hospital_id"] != u["hospital_id"]):
        raise HTTPException(404, "Alert not found.")
    if b.value not in ("Awaiting", "Received", "Admitted"):
        raise HTTPException(400, "Invalid hand-off status.")
    if b.value == "Admitted" and a["handoff"] != "Admitted":
        ex("UPDATE hospitals SET beds_free=MAX(0,beds_free-1) WHERE id=?", (a["hospital_id"],))
    ex("UPDATE alerts SET handoff=? WHERE id=?", (b.value, aid))
    return alert_out(q("SELECT * FROM alerts WHERE id=?", (aid,), one=True))

# ---------------------------------------------------------------- fleet, hospital, admin
@app.get("/api/ambulances")
def ambulances(u=Depends(current)):
    need(u, "responder", "admin")
    return q("SELECT * FROM ambulances")

@app.put("/api/ambulances/{amb_id}")
def set_ambulance(amb_id: int, b: ValueIn, u=Depends(current)):
    need(u, "responder", "admin")
    if b.value not in ("Available", "Assigned", "En Route", "Transporting", "Off Duty"):
        raise HTTPException(400, "Invalid ambulance status.")
    ex("UPDATE ambulances SET status=? WHERE id=?", (b.value, amb_id))
    return {"ok": True}

@app.get("/api/hospital")
def my_hospital(u=Depends(current)):
    need(u, "hospital")
    return q("SELECT * FROM hospitals WHERE id=?", (u["hospital_id"],), one=True)

@app.put("/api/hospital")
def update_hospital(b: HospitalIn, u=Depends(current)):
    need(u, "hospital")
    h = q("SELECT * FROM hospitals WHERE id=?", (u["hospital_id"],), one=True)
    if b.readiness and b.readiness not in ("Ready", "Busy", "Diverted"):
        raise HTTPException(400, "Invalid readiness.")
    ex("UPDATE hospitals SET readiness=?, beds_free=?, icu_free=? WHERE id=?",
       (b.readiness or h["readiness"],
        max(0, min(h["beds_total"], b.beds_free if b.beds_free is not None else h["beds_free"])),
        max(0, b.icu_free if b.icu_free is not None else h["icu_free"]), h["id"]))
    return q("SELECT * FROM hospitals WHERE id=?", (h["id"],), one=True)

@app.get("/api/admin/stats")
def stats(u=Depends(current)):
    need(u, "admin")
    n = lambda sql: q(sql, one=True)["n"]
    return {"total": n("SELECT COUNT(*) n FROM alerts"),
            "active": n("SELECT COUNT(*) n FROM alerts WHERE stage!='hospital_reached'"),
            "completed": n("SELECT COUNT(*) n FROM alerts WHERE stage='hospital_reached'"),
            "patients": n("SELECT COUNT(*) n FROM users WHERE role='patient'"),
            "ambulances": q("SELECT * FROM ambulances"), "hospitals": q("SELECT * FROM hospitals")}

app.mount("/", StaticFiles(directory=BASE.parent / "frontend", html=True), name="frontend")
```

```text
# backend/requirements.txt
fastapi>=0.110
uvicorn[standard]>=0.29
```

```html
<!-- frontend/index.html -->
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mediflow Sentinel</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.css">
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="style.css">
</head>
<body>
<section id="auth" class="auth">
  <div class="auth-brand">
    <div class="logo"><span class="cross"></span>Mediflow Sentinel</div>
    <h1>From the first alert to hospital hand-off, everyone sees the same picture.</h1>
    <p>AI-Powered Smart Emergency Response System connecting patients, caregivers, ambulance responders and hospitals.</p>
    <p class="small">Prototype with simulated ambulance and bed data. Not for real emergencies.</p>
  </div>
  <div class="auth-card">
    <div class="seg" role="tablist">
      <button id="modeLogin" class="on" type="button">Sign in</button>
      <button id="modeReg" type="button">Create account</button>
    </div>
    <form id="authForm" autocomplete="on">
      <div id="regOnly" hidden>
        <label>Full name<input id="fName" autocomplete="name"></label>
        <label>I am a
          <select id="fRole">
            <option value="patient">Patient</option>
            <option value="caregiver">Caregiver</option>
            <option value="responder">Emergency responder</option>
            <option value="hospital">Hospital staff</option>
          </select></label>
        <label>Phone<input id="fPhone" type="tel" autocomplete="tel"></label>
        <label id="rowPatient" hidden>Patient's email (to link their profile)<input id="fPatient" type="email"></label>
        <label id="rowHospital" hidden>Hospital<select id="fHospital"></select></label>
      </div>
      <label>Email<input id="fEmail" type="email" required autocomplete="email"></label>
      <label>Password<input id="fPass" type="password" required minlength="6" autocomplete="current-password"></label>
      <p id="authErr" class="err" role="alert"></p>
      <button class="btn primary wide" id="authBtn">Sign in</button>
    </form>
    <div class="demo" id="demoBox">
      <span>Demo accounts (password demo123)</span>
      <div>
        <button type="button" data-demo="patient">Patient</button>
        <button type="button" data-demo="caregiver">Caregiver</button>
        <button type="button" data-demo="responder">Responder</button>
        <button type="button" data-demo="hospital">Hospital</button>
        <button type="button" data-demo="admin">Admin</button>
      </div>
    </div>
  </div>
</section>

<div id="app" hidden>
  <header class="top">
    <div class="logo"><span class="cross"></span>Mediflow Sentinel</div>
    <div class="who"><span id="whoName"></span><span id="whoRole" class="pill"></span>
      <button class="btn ghost" id="logout" type="button">Sign out</button></div>
  </header>
  <nav id="tabs" class="tabs"></nav>
  <main id="main"></main>
</div>

<dialog id="sosDlg">
  <form method="dialog" id="sosForm">
    <h2>Send emergency alert</h2>
    <p class="muted">Your GPS location is shared with responders once you allow it.</p>
    <div class="chips" id="chips">
      <button type="button" data-s="Unconscious">Unconscious</button>
      <button type="button" data-s="Chest pain">Chest pain</button>
      <button type="button" data-s="Difficulty breathing">Difficulty breathing</button>
      <button type="button" data-s="Severe bleeding">Severe bleeding</button>
      <button type="button" data-s="Accident">Accident</button>
      <button type="button" data-s="Fainted">Fainted</button>
    </div>
    <label>Anything else responders should know?<textarea id="sosNotes" rows="3"></textarea></label>
    <div class="row-end">
      <button type="button" class="btn ghost" id="sosCancel">Cancel</button>
      <button type="submit" class="btn danger" id="sosSend">Send SOS now</button>
    </div>
  </form>
</dialog>
<div id="toast" role="status"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.js"></script>
<script src="app.js"></script>
</body>
</html>
```

```css
/* frontend/style.css */
:root{--navy:#0A2A5E;--blue:#0B4FA8;--blue2:#E6EFFB;--red:#D7263D;--red2:#FDECEE;--ink:#14213D;--mute:#5B6B88;
--line:#D9E3F1;--bg:#F3F7FC;--ok:#1E8E5A;--warn:#C77700;font-family:Manrope,system-ui,sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-size:15px;line-height:1.5}
button,input,select,textarea{font:inherit;color:inherit}
:focus-visible{outline:3px solid #6AA4F5;outline-offset:2px}
[hidden]{display:none!important}
h1,h2,h3{line-height:1.2;margin:0 0 .5rem}h2{font-size:1.15rem}h3{font-size:1rem}
.muted,.small{color:var(--mute)}.small{font-size:.82rem}
.logo{display:flex;align-items:center;gap:.6rem;font-weight:800;font-size:1.1rem}
.cross{width:26px;height:26px;border-radius:7px;background:var(--red);position:relative;flex:none}
.cross:before,.cross:after{content:"";position:absolute;background:#fff;border-radius:2px}
.cross:before{left:11px;top:5px;width:4px;height:16px}.cross:after{left:5px;top:11px;width:16px;height:4px}
/* auth */
.auth{min-height:100vh;display:grid;grid-template-columns:1.1fr 1fr}
.auth-brand{background:var(--navy);color:#fff;padding:3rem;display:flex;flex-direction:column;justify-content:center;gap:1rem}
.auth-brand h1{font-size:clamp(1.7rem,3.2vw,2.6rem);max-width:18ch;font-weight:800}
.auth-brand p{max-width:46ch;color:#C9D8F0}.auth-brand .small{color:#9FB6DB}
.auth-card{padding:2.5rem;max-width:460px;margin:auto;width:100%}
.seg{display:flex;background:var(--blue2);border-radius:10px;padding:4px;margin-bottom:1.2rem}
.seg button{flex:1;border:0;background:none;padding:.55rem;border-radius:8px;font-weight:700;color:var(--mute);cursor:pointer}
.seg button.on{background:#fff;color:var(--blue);box-shadow:0 1px 3px rgba(10,42,94,.15)}
label{display:block;font-weight:700;font-size:.85rem;margin-bottom:.8rem}
input,select,textarea{display:block;width:100%;margin-top:.3rem;padding:.65rem .75rem;border:1px solid var(--line);border-radius:8px;background:#fff;font-weight:500}
.err{color:var(--red);min-height:1.2rem;margin:.2rem 0 .6rem;font-weight:600}
.demo{margin-top:1.4rem;font-size:.82rem;color:var(--mute)}
.demo div{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.4rem}
.demo button{border:1px solid var(--line);background:#fff;padding:.3rem .7rem;border-radius:999px;cursor:pointer;font-weight:600;color:var(--blue)}
/* buttons */
.btn{border:0;border-radius:9px;padding:.6rem 1rem;font-weight:700;cursor:pointer;background:var(--blue2);color:var(--blue)}
.btn.primary{background:var(--blue);color:#fff}.btn.danger{background:var(--red);color:#fff}
.btn.ghost{background:transparent;border:1px solid var(--line);color:var(--ink)}
.btn.wide{width:100%}.btn.sm{padding:.35rem .7rem;font-size:.85rem}.btn:disabled{opacity:.5;cursor:default}
/* shell */
.top{background:var(--navy);color:#fff;display:flex;justify-content:space-between;align-items:center;padding:.8rem 1.5rem;gap:1rem;flex-wrap:wrap}
.top .btn.ghost{color:#fff;border-color:#47629A}.who{display:flex;align-items:center;gap:.7rem}
.pill{background:#1B4A91;border-radius:999px;padding:.15rem .7rem;font-size:.78rem;font-weight:700}
.tabs{background:#fff;border-bottom:1px solid var(--line);display:flex;gap:.3rem;padding:0 1.2rem;overflow-x:auto}
.tabs button{border:0;background:none;padding:.9rem 1rem;font-weight:700;color:var(--mute);cursor:pointer;border-bottom:3px solid transparent;white-space:nowrap}
.tabs button.on{color:var(--blue);border-color:var(--red)}
main{max-width:1200px;margin:0 auto;padding:1.5rem 1.2rem 3rem}
.grid2{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.2fr);gap:1.2rem;align-items:start}
.grid-list{display:grid;grid-template-columns:320px minmax(0,1fr);gap:1.2rem;align-items:start}
.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:1.2rem}
.card+.card{margin-top:1.2rem}
dl{display:grid;grid-template-columns:auto 1fr;gap:.35rem 1rem;margin:0}dt{color:var(--mute);font-weight:600}dd{margin:0;font-weight:600}
/* SOS */
.sos-wrap{display:flex;flex-direction:column;align-items:center;text-align:center;padding:2rem 1rem}
.sos{width:min(250px,64vw);aspect-ratio:1;border-radius:50%;border:0;background:var(--red);color:#fff;font-size:3rem;font-weight:800;letter-spacing:.04em;cursor:pointer;
box-shadow:0 0 0 14px var(--red2),0 12px 30px rgba(215,38,61,.35);animation:pulse 2.4s ease-out infinite}
.sos small{display:block;font-size:.85rem;font-weight:600;letter-spacing:0}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(215,38,61,.45),0 12px 30px rgba(215,38,61,.35)}70%{box-shadow:0 0 0 28px rgba(215,38,61,0),0 12px 30px rgba(215,38,61,.35)}100%{box-shadow:0 0 0 0 rgba(215,38,61,0),0 12px 30px rgba(215,38,61,.35)}}
@media(prefers-reduced-motion:reduce){.sos{animation:none}}
/* badges */
.badge{display:inline-block;padding:.15rem .65rem;border-radius:999px;font-size:.8rem;font-weight:800}
.p-Critical{background:var(--red);color:#fff}.p-High{background:var(--red2);color:var(--red)}
.p-Medium{background:#FFF3DC;color:var(--warn)}.p-Low{background:#E3F5EC;color:var(--ok)}
.notice{background:var(--blue2);border-radius:10px;padding:.6rem .8rem;font-size:.85rem;color:var(--navy);margin-top:.8rem}
/* tracker */
.track{list-style:none;margin:0;padding:0}
.track li{position:relative;padding:0 0 1.1rem 2.2rem;color:var(--mute);font-weight:600}
.track li:before{content:"";position:absolute;left:5px;top:20px;bottom:-2px;width:2px;background:var(--line)}
.track li:last-child:before{display:none}
.track li i{position:absolute;left:0;top:2px;width:12px;height:12px;border-radius:50%;background:#fff;border:2px solid var(--line);box-sizing:content-box}
.track li.done{color:var(--ink)}.track li.done i{background:var(--blue);border-color:var(--blue)}
.track li.done:before{background:var(--blue)}
.track li.now i{background:var(--red);border-color:var(--red);box-shadow:0 0 0 5px var(--red2)}
.track time{display:block;font-weight:500;font-size:.8rem;color:var(--mute)}
.eta{display:flex;justify-content:space-between;align-items:center;background:var(--navy);color:#fff;border-radius:12px;padding:.8rem 1rem;margin:.4rem 0 1rem}
.eta b{font-size:1.5rem}
#mapslot{height:340px;border-radius:12px;overflow:hidden;border:1px solid var(--line);margin-top:1rem}
#map{height:100%;width:100%}
.pin{width:30px;height:30px;border-radius:50%;display:grid;place-items:center;color:#fff;font-weight:800;border:3px solid #fff;box-shadow:0 2px 6px rgba(0,0,0,.35);font-size:.8rem}
.pin.r{background:var(--red)}.pin.b{background:var(--blue)}.pin.n{background:var(--navy)}
/* lists + tables */
.alist{display:grid;gap:.6rem}
.aitem{text-align:left;width:100%;background:#fff;border:1px solid var(--line);border-radius:12px;padding:.8rem;cursor:pointer;display:grid;gap:.25rem}
.aitem.on{border-color:var(--blue);box-shadow:0 0 0 2px var(--blue2)}
.aitem .r{display:flex;justify-content:space-between;align-items:center;font-weight:700}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:1rem;margin-bottom:1.2rem}
.stat{background:#fff;border:1px solid var(--line);border-radius:14px;padding:1rem 1.2rem}
.stat b{display:block;font-size:2rem;line-height:1.1;color:var(--blue)}.stat.red b{color:var(--red)}
.tbl{width:100%;border-collapse:collapse;font-size:.9rem}
.tbl th,.tbl td{text-align:left;padding:.55rem .5rem;border-bottom:1px solid var(--line)}
.tbl th{color:var(--mute);font-weight:700}
.wrap-x{overflow-x:auto}
.actions{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:1rem}
.stepper{display:inline-flex;align-items:center;gap:.6rem}.stepper b{min-width:2ch;text-align:center;font-size:1.3rem}
.cap{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:1.2rem}
.empty{text-align:center;color:var(--mute);padding:2rem 1rem}
/* dialog + chips + toast */
dialog{border:0;border-radius:16px;padding:1.4rem;width:min(480px,92vw)}dialog::backdrop{background:rgba(10,42,94,.5)}
.chips{display:flex;flex-wrap:wrap;gap:.4rem;margin:.8rem 0}
.chips button{border:1px solid var(--line);background:#fff;border-radius:999px;padding:.35rem .8rem;cursor:pointer;font-weight:600}
.chips button.on{background:var(--red);border-color:var(--red);color:#fff}
.row-end{display:flex;justify-content:flex-end;gap:.5rem}
#toast{position:fixed;left:50%;bottom:1.2rem;transform:translateX(-50%);background:var(--navy);color:#fff;padding:.6rem 1.1rem;border-radius:10px;opacity:0;pointer-events:none;transition:opacity .2s;z-index:9999;max-width:90vw}
#toast.show{opacity:1}
@media(max-width:860px){.auth{grid-template-columns:1fr}.auth-brand{padding:2rem 1.5rem}.grid2,.grid-list{grid-template-columns:1fr}.sos-wrap{padding:1rem}}
```

```javascript
// frontend/app.js
/* Mediflow Sentinel frontend (plain JS). Talks to the FastAPI backend at /api. */
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const STAGES = [["created", "SOS alert created"], ["acknowledged", "Alert acknowledged"], ["dispatched", "Ambulance dispatched"],
  ["picked_up", "Patient picked up"], ["hospital_reached", "Hospital reached"]];
const NEXT_LABEL = { acknowledged: "Accept alert", dispatched: "Dispatch ambulance", picked_up: "Mark patient picked up", hospital_reached: "Mark hospital reached" };
const ROLE_LABEL = { patient: "Patient", caregiver: "Caregiver", responder: "Responder", hospital: "Hospital", admin: "Admin" };
const TABS = { patient: [["home", "Emergency"], ["profile", "Health profile"]], caregiver: [["home", "Emergency"], ["profile", "Profile"]],
  responder: [["alerts", "Incoming alerts"], ["fleet", "Ambulances"]], hospital: [["incoming", "Incoming patients"], ["capacity", "Readiness and beds"]],
  admin: [["overview", "Overview"]] };
const PRIORITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

let token = localStorage.getItem("ms_token"), me = null, tab = "", sel = null, D = {}, regMode = false;
let mapEl, mapObj, mapLayer, lastFit = null, timer = null;

async function api(path, { method = "GET", body } = {}) {
  const r = await fetch("/api" + path, { method, headers: { "Content-Type": "application/json", ...(token ? { Authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { if (r.status === 401 && token) logout(); throw new Error(typeof j.detail === "string" ? j.detail : "Check the details and try again."); }
  return j;
}
function toast(m) { const t = $("#toast"); t.textContent = m; t.classList.add("show"); clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove("show"), 3200); }
const fmtTime = s => s ? new Date(s * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "";

/* ---------------- auth ---------------- */
function setMode(reg) {
  regMode = reg; $("#modeLogin").classList.toggle("on", !reg); $("#modeReg").classList.toggle("on", reg);
  $("#regOnly").hidden = !reg; $("#authBtn").textContent = reg ? "Create account" : "Sign in"; $("#demoBox").hidden = reg; $("#authErr").textContent = "";
  $("#fPass").autocomplete = reg ? "new-password" : "current-password"; roleFields();
}
function roleFields() { const r = $("#fRole").value; $("#rowPatient").hidden = !(regMode && r === "caregiver"); $("#rowHospital").hidden = !(regMode && r === "hospital"); }
$("#modeLogin").onclick = () => setMode(false); $("#modeReg").onclick = () => setMode(true); $("#fRole").onchange = roleFields;
document.querySelectorAll("[data-demo]").forEach(b => b.onclick = () => { $("#fEmail").value = b.dataset.demo + "@demo.com"; $("#fPass").value = "demo123"; });
$("#authForm").onsubmit = async e => {
  e.preventDefault(); $("#authErr").textContent = "";
  try {
    const res = regMode
      ? await api("/register", { method: "POST", body: { name: $("#fName").value, email: $("#fEmail").value, password: $("#fPass").value, role: $("#fRole").value, phone: $("#fPhone").value || null, patient_email: $("#fPatient").value || null, hospital_id: +$("#fHospital").value || null } })
      : await api("/login", { method: "POST", body: { email: $("#fEmail").value, password: $("#fPass").value } });
    token = res.token; localStorage.setItem("ms_token", token); start();
  } catch (err) { $("#authErr").textContent = err.message; }
};
function logout() { token = null; me = null; localStorage.removeItem("ms_token"); clearInterval(timer); $("#app").hidden = true; $("#auth").hidden = false; }
$("#logout").onclick = logout;
fetch("/api/hospitals").then(r => r.json()).then(h => $("#fHospital").innerHTML = h.map(x => `<option value="${x.id}">${esc(x.name)}</option>`).join("")).catch(() => {});

async function start() {
  try { me = await api("/me"); } catch { return logout(); }
  $("#auth").hidden = true; $("#app").hidden = false; $("#whoName").textContent = me.name; $("#whoRole").textContent = ROLE_LABEL[me.role];
  tab = TABS[me.role][0][0]; sel = null; lastFit = null; drawTabs(); await refresh(true);
  clearInterval(timer); timer = setInterval(() => refresh(false), 3000);
}
function drawTabs() {
  $("#tabs").innerHTML = TABS[me.role].map(([k, l]) => `<button class="${k === tab ? "on" : ""}" data-tab="${k}">${l}</button>`).join("");
  document.querySelectorAll("[data-tab]").forEach(b => b.onclick = () => { tab = b.dataset.tab; drawTabs(); refresh(true); });
}

/* ---------------- data ---------------- */
async function refresh(force) {
  try {
    const r = me.role;
    if (r === "admin") { [D.stats, D.alerts] = await Promise.all([api("/admin/stats"), api("/alerts")]); }
    else {
      D.alerts = await api("/alerts");
      if (r === "responder") D.fleet = await api("/ambulances");
      if (r === "hospital") D.hospital = await api("/hospital");
    }
  } catch (e) { return; }
  const busy = document.activeElement && ["SELECT", "INPUT", "TEXTAREA"].includes(document.activeElement.tagName) && $("#main").contains(document.activeElement);
  if (force || (!busy && tab !== "profile")) render();
}
function selected() {
  const list = D.alerts || [];
  if (me.role === "patient" || me.role === "caregiver") return list.find(a => a.stage !== "hospital_reached") || null;
  return list.find(a => a.id === sel) || null;
}

/* ---------------- views ---------------- */
function render() {
  const m = $("#main"), r = me.role;
  if (r === "patient" || r === "caregiver") m.innerHTML = tab === "profile" ? profileView() : citizenHome();
  else if (r === "responder") m.innerHTML = tab === "fleet" ? fleetView() : listDetail("responder");
  else if (r === "hospital") m.innerHTML = tab === "capacity" ? capacityView() : listDetail("hospital");
  else m.innerHTML = adminView();
  mountMap(); bind();
}
const badge = p => `<span class="badge p-${p}">${p} priority</span>`;

function citizenHome() {
  const a = selected();
  if (!a) {
    const past = (D.alerts || []).slice(0, 5);
    return `<div class="grid2"><div class="card sos-wrap"><button class="sos" data-act="sos" aria-label="Send emergency SOS">SOS<small>Tap to get help</small></button>
      <p class="muted" style="max-width:34ch">Responders get your location and health profile the moment you send an alert.</p></div>
      <div class="card"><h2>Recent alerts</h2>${past.length ? `<table class="tbl"><tr><th>Time</th><th>Priority</th><th>Outcome</th></tr>${past.map(x => `<tr><td>${fmtTime(x.times.created)}</td><td>${badge(x.priority)}</td><td>${esc(x.status_label)}</td></tr>`).join("")}</table>` : `<p class="empty">No alerts yet. Your health profile is ready when you need it.</p>`}</div></div>`;
  }
  return alertPanel(a, "");
}

function alertPanel(a, actions) {
  const p = a.patient || {}, idx = STAGES.findIndex(s => s[0] === a.stage);
  const steps = STAGES.map(([k, l], i) => `<li class="${i <= idx ? "done" : ""} ${i === idx ? "now" : ""}"><i></i>${l}${a.times[k] ? `<time>${fmtTime(a.times[k])}</time>` : ""}</li>`).join("");
  const eta = a.eta_min === null ? "Awaiting dispatch" : a.eta_min === 0 ? "Arrived" : `${a.eta_min} min`;
  return `<div class="grid2"><div>
    <div class="card"><h2>Emergency alert #${a.id} ${badge(a.priority)}</h2>
      <dl><dt>Reported</dt><dd>${esc(a.description)}</dd><dt>Location</dt><dd>${a.lat.toFixed(4)}, ${a.lng.toFixed(4)}${a.located ? "" : " (demo location)"}</dd>
      <dt>Ambulance</dt><dd>${a.ambulance ? `${esc(a.ambulance.code)} · ${esc(a.ambulance.driver)}` : "Not assigned"}</dd>
      <dt>Hospital</dt><dd>${a.hospital ? `${esc(a.hospital.name)} (${esc(a.hospital.readiness)})` : "Not assigned"}</dd>
      <dt>Hand-off</dt><dd>${esc(a.handoff)}</dd></dl>
      <h3 style="margin-top:1rem">AI triage suggestion</h3>
      <p style="margin:.2rem 0">Suggested urgency: <b>${a.priority}</b> (score ${a.score}/100)</p>
      <ul style="margin:.2rem 0;padding-left:1.1rem">${a.reasons.map(x => `<li>${esc(x)}</li>`).join("")}</ul>
      <div class="notice">${esc(a.disclaimer)}</div></div>
    <div class="card"><h2>Patient health profile</h2><dl><dt>Name</dt><dd>${esc(p.name)}</dd><dt>Age</dt><dd>${esc(p.age || "Not added")}</dd>
      <dt>Blood group</dt><dd>${esc(p.blood_group || "Not added")}</dd><dt>Allergies</dt><dd>${esc(p.allergies || "None listed")}</dd>
      <dt>History</dt><dd>${esc(p.history || "None listed")}</dd><dt>Emergency contact</dt><dd>${esc(p.emergency_contact || "Not added")}</dd></dl></div></div>
    <div class="card"><h2>Response tracking</h2><ol class="track">${steps}</ol>
      <div class="eta"><span>${esc(a.status_label)}</span><b>${eta}</b></div><small class="muted">ETA and ambulance position are simulated for this demo.</small>
      <div id="mapslot"></div>${actions ? `<div class="actions">${actions}</div>` : ""}</div></div>`;
}

function listDetail(role) {
  const list = [...(D.alerts || [])].sort((x, y) => (x.stage === "hospital_reached") - (y.stage === "hospital_reached") || PRIORITY_ORDER[x.priority] - PRIORITY_ORDER[y.priority] || y.id - x.id);
  if (!sel && list.length) sel = list[0].id;
  const a = selected();
  const items = list.length ? list.map(x => `<button class="aitem ${x.id === sel ? "on" : ""}" data-act="sel" data-id="${x.id}"><div class="r"><span>#${x.id} ${esc(x.patient?.name)}</span>${badge(x.priority)}</div>
    <span class="muted">${esc(x.description)}</span><span class="small">${STAGES.find(s => s[0] === x.stage)[1]}${role === "hospital" ? " · hand-off " + esc(x.handoff) : ""}</span></button>`).join("")
    : `<div class="card empty">No alerts right now. New SOS alerts appear here instantly.</div>`;
  let actions = "";
  if (a && role === "responder") {
    const nxt = STAGES[STAGES.findIndex(s => s[0] === a.stage) + 1];
    actions = nxt ? `<button class="btn primary" data-act="stage" data-id="${a.id}" data-stage="${nxt[0]}">${NEXT_LABEL[nxt[0]]}</button>` : `<span class="muted">Case complete.</span>`;
  }
  if (a && role === "hospital") {
    actions = ["Received", "Admitted"].map(v => `<button class="btn ${a.handoff === v ? "primary" : ""}" data-act="handoff" data-id="${a.id}" data-v="${v}">Mark ${v.toLowerCase()}</button>`).join("");
  }
  return `<div class="grid-list"><div class="alist">${items}</div><div>${a ? alertPanel(a, actions) : ""}</div></div>`;
}

function fleetView() {
  const opts = ["Available", "Assigned", "En Route", "Transporting", "Off Duty"];
  return `<div class="card wrap-x"><h2>Ambulance status</h2><table class="tbl"><tr><th>Unit</th><th>Driver</th><th>Status</th></tr>${(D.fleet || []).map(f => `<tr><td><b>${esc(f.code)}</b></td><td>${esc(f.driver)}</td>
    <td><select data-amb="${f.id}" aria-label="Status for ${esc(f.code)}">${opts.map(o => `<option ${o === f.status ? "selected" : ""}>${o}</option>`).join("")}</select></td></tr>`).join("")}</table></div>`;
}

function capacityView() {
  const h = D.hospital; if (!h) return "";
  const step = (f, l, v) => `<div class="card"><h3>${l}</h3><div class="stepper"><button class="btn sm" data-act="bed" data-f="${f}" data-d="-1" aria-label="Decrease ${l}">−</button><b>${v}</b><button class="btn sm" data-act="bed" data-f="${f}" data-d="1" aria-label="Increase ${l}">+</button></div></div>`;
  return `<h2>${esc(h.name)}</h2><div class="cap"><div class="card"><h3>Hospital readiness</h3><select data-ready>${["Ready", "Busy", "Diverted"].map(o => `<option ${o === h.readiness ? "selected" : ""}>${o}</option>`).join("")}</select>
    <p class="small muted">Diverted hospitals are skipped when new alerts are assigned.</p></div>${step("beds_free", "Beds free (simulated)", h.beds_free)}${step("icu_free", "ICU beds free (simulated)", h.icu_free)}
    <div class="card"><h3>Total beds</h3><b style="font-size:1.5rem">${h.beds_total}</b></div></div>`;
}

function adminView() {
  const s = D.stats; if (!s) return "";
  const cnt = k => s.ambulances.filter(a => a.status === k).length;
  return `<div class="stats"><div class="stat"><b>${s.total}</b>Total emergency alerts</div><div class="stat red"><b>${s.active}</b>Active emergencies</div>
    <div class="stat"><b>${s.completed}</b>Completed cases</div><div class="stat"><b>${s.patients}</b>Registered patients</div></div>
  <div class="grid2"><div class="card wrap-x"><h2>Ambulances (${cnt("Available")} of ${s.ambulances.length} available)</h2><table class="tbl"><tr><th>Unit</th><th>Driver</th><th>Status</th></tr>${s.ambulances.map(a => `<tr><td><b>${esc(a.code)}</b></td><td>${esc(a.driver)}</td><td>${esc(a.status)}</td></tr>`).join("")}</table></div>
  <div class="card wrap-x"><h2>Hospitals</h2><table class="tbl"><tr><th>Name</th><th>Readiness</th><th>Beds</th><th>ICU</th></tr>${s.hospitals.map(h => `<tr><td>${esc(h.name)}</td><td>${esc(h.readiness)}</td><td>${h.beds_free}/${h.beds_total}</td><td>${h.icu_free}</td></tr>`).join("")}</table></div></div>
  <div class="card wrap-x"><h2>Recent alerts</h2>${(D.alerts || []).length ? `<table class="tbl"><tr><th>#</th><th>Patient</th><th>Priority</th><th>Stage</th><th>Hospital</th></tr>${D.alerts.slice(0, 12).map(a => `<tr><td>${a.id}</td><td>${esc(a.patient?.name)}</td><td>${badge(a.priority)}</td><td>${STAGES.find(x => x[0] === a.stage)[1]}</td><td>${esc(a.hospital?.name)}</td></tr>`).join("")}</table>` : `<p class="empty">No alerts yet. Trigger one from the patient account.</p>`}</div>`;
}

function profileView() {
  const u = me, pat = u.role === "patient";
  const bg = ["", "A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"];
  return `<form class="card" id="profForm" style="max-width:640px"><h2>${pat ? "Patient health profile" : "Your profile"}</h2>
    ${u.role === "caregiver" ? `<p class="muted">Linked patient: ${esc(u.linked_patient_name || "None. Alerts you send use your own profile.")}</p>` : ""}
    <label>Full name<input name="name" value="${esc(u.name)}" required></label><label>Phone<input name="phone" value="${esc(u.phone)}" type="tel"></label>
    ${pat ? `<label>Age<input name="age" type="number" min="0" max="120" value="${esc(u.age)}"></label>
    <label>Blood group<select name="blood_group">${bg.map(b => `<option value="${b}" ${b === u.blood_group ? "selected" : ""}>${b || "Select"}</option>`).join("")}</select></label>
    <label>Allergies<input name="allergies" value="${esc(u.allergies)}"></label><label>Medical history<textarea name="history" rows="3">${esc(u.history)}</textarea></label>
    <label>Emergency contact number<input name="emergency_contact" type="tel" value="${esc(u.emergency_contact)}"></label>` : ""}
    <button class="btn primary">Save profile</button></form>`;
}

/* ---------------- map ---------------- */
function mountMap() {
  const slot = $("#mapslot"), a = selected(); if (!slot || !a || typeof L === "undefined") return;
  if (!mapEl) {
    mapEl = document.createElement("div"); mapEl.id = "map"; mapObj = L.map(mapEl);
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 19, attribution: "© OpenStreetMap" }).addTo(mapObj); mapLayer = L.layerGroup().addTo(mapObj);
  }
  slot.appendChild(mapEl); mapObj.invalidateSize(); mapLayer.clearLayers();
  const pin = (c, t) => L.divIcon({ className: "", html: `<div class="pin ${c}">${t}</div>`, iconSize: [30, 30], iconAnchor: [15, 15] });
  const P = [a.lat, a.lng], H = a.hosp_pos, A = a.amb_pos;
  L.marker(P, { icon: pin("r", "P") }).bindTooltip("Patient").addTo(mapLayer);
  L.marker(H, { icon: pin("n", "H") }).bindTooltip(a.hospital ? a.hospital.name : "Hospital").addTo(mapLayer);
  L.marker(A, { icon: pin("b", "A") }).bindTooltip("Ambulance (simulated)").addTo(mapLayer);
  const target = ["picked_up", "hospital_reached"].includes(a.stage) ? H : P;
  L.polyline([A, target], { color: "#0B4FA8", dashArray: "6 8", weight: 3 }).addTo(mapLayer);
  if (lastFit !== a.id) { mapObj.fitBounds(L.latLngBounds([P, H, A]).pad(0.3)); lastFit = a.id; }
}

/* ---------------- actions ---------------- */
function bind() {
  $("#main").onclick = async e => {
    const b = e.target.closest("[data-act]"); if (!b) return; const act = b.dataset.act;
    try {
      if (act === "sos") openSos();
      else if (act === "sel") { sel = +b.dataset.id; render(); }
      else if (act === "stage") { await api(`/alerts/${b.dataset.id}/stage`, { method: "POST", body: { stage: b.dataset.stage } }); toast("Status updated"); await refresh(true); }
      else if (act === "handoff") { await api(`/alerts/${b.dataset.id}/handoff`, { method: "POST", body: { value: b.dataset.v } }); toast("Hand-off updated"); await refresh(true); }
      else if (act === "bed") { const h = D.hospital; await api("/hospital", { method: "PUT", body: { [b.dataset.f]: h[b.dataset.f] + +b.dataset.d } }); await refresh(true); }
    } catch (err) { toast(err.message); }
  };
  document.querySelectorAll("[data-amb]").forEach(s => s.onchange = async () => { try { await api("/ambulances/" + s.dataset.amb, { method: "PUT", body: { value: s.value } }); toast("Ambulance status updated"); await refresh(true); } catch (e) { toast(e.message); } });
  const rd = $("[data-ready]"); if (rd) rd.onchange = async () => { try { await api("/hospital", { method: "PUT", body: { readiness: rd.value } }); toast("Readiness updated"); await refresh(true); } catch (e) { toast(e.message); } };
  const pf = $("#profForm"); if (pf) pf.onsubmit = async e => {
    e.preventDefault(); const f = Object.fromEntries(new FormData(pf)); f.age = f.age ? +f.age : null;
    try { me = await api("/profile", { method: "PUT", body: f }); $("#whoName").textContent = me.name; toast("Profile saved"); } catch (err) { toast(err.message); }
  };
}

/* ---------------- SOS ---------------- */
const dlg = $("#sosDlg");
function openSos() { document.querySelectorAll("#chips button").forEach(b => b.classList.remove("on")); $("#sosNotes").value = ""; dlg.showModal(); }
document.querySelectorAll("#chips button").forEach(b => b.onclick = () => b.classList.toggle("on"));
$("#sosCancel").onclick = () => dlg.close();
function getPos() {
  return new Promise(res => {
    if (!navigator.geolocation) return res(null);
    navigator.geolocation.getCurrentPosition(p => res({ lat: p.coords.latitude, lng: p.coords.longitude }), () => res(null), { enableHighAccuracy: true, timeout: 8000 });
  });
}
$("#sosForm").onsubmit = async e => {
  e.preventDefault(); const btn = $("#sosSend"); btn.disabled = true; btn.textContent = "Getting location...";
  const pos = await getPos(); if (!pos) toast("Location blocked or unavailable. Using a demo location.");
  const loc = pos || { lat: 12.9716, lng: 77.5946 };
  try {
    await api("/sos", { method: "POST", body: { ...loc, located: !!pos, symptoms: [...document.querySelectorAll("#chips .on")].map(b => b.dataset.s), notes: $("#sosNotes").value } });
    dlg.close(); toast("SOS sent. Help is being coordinated."); lastFit = null; await refresh(true);
  } catch (err) { toast(err.message); }
  btn.disabled = false; btn.textContent = "Send SOS now";
};

if (token) start();
```