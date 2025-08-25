# main.py
import os, re, time, json, sqlite3
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, Query, HTTPException, BackgroundTasks, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# ---------------------------
# Env + optional OpenAI client
# ---------------------------
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
PROVIDER = os.getenv("PROVIDER", "mock").lower()  # "openai" or "mock"
USE_OPENAI = bool(OPENAI_API_KEY) and PROVIDER == "openai"

if USE_OPENAI:
    try:
        from openai import OpenAI
        openai_client = OpenAI(api_key=OPENAI_API_KEY)
    except Exception:
        USE_OPENAI = False

# ---------------------------
# App + CORS
# ---------------------------
app = FastAPI(title="GuardRail Wrapper (MVP)")

ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://guardrail-admin.vercel.app",   # your Vercel UI
    "dayronknows.me"
    # add your Squarespace domain if embedding:
    # "https://<your-site>.squarespace.com",
    # "https://www.<your-domain>.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Preflight (belt & suspenders)
@app.options("/{rest_of_path:path}")
def options_catchall(rest_of_path: str) -> Response:
    return Response(status_code=204)

# ---------------------------
# SQLite storage
# ---------------------------
DB_PATH = os.getenv("DB_PATH", "guardrail.db")

def db_exec(sql: str, params: tuple = ()):
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        conn.commit()
        return cur
    finally:
        conn.close()

def db_query(sql: str, params: tuple = ()):
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur.fetchall()
    finally:
        conn.close()

def ensure_schema():
    db_exec(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            provider TEXT,
            input_text TEXT,
            raw_output TEXT,
            redacted_output TEXT,
            flagged INTEGER,
            redactions_json TEXT
        )
        """
    )

ensure_schema()

# ---------------------------
# PII redaction helpers
# ---------------------------
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")
SSN_RE   = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

def redact_pii(text: str) -> Dict[str, Any]:
    redactions: List[Dict[str, str]] = []

    def repl_email(m):
        redactions.append({"type": "email", "value": m.group(0)})
        return "[REDACTED_EMAIL]"

    def repl_phone(m):
        redactions.append({"type": "phone", "value": m.group(0)})
        return "[REDACTED_PHONE]"

    def repl_ssn(m):
        redactions.append({"type": "ssn", "value": m.group(0)})
        return "[REDACTED_SSN]"

    out = EMAIL_RE.sub(repl_email, text)
    out = PHONE_RE.sub(repl_phone, out)
    out = SSN_RE.sub(repl_ssn, out)

    return {
        "output": out,
        "flagged": bool(redactions),
        "redactions": redactions,
        "checks_ran": ["pii_redaction_v1"],
    }

# ---------------------------
# Models
# ---------------------------
class ScanRequest(BaseModel):
    prompt: str

class ChatRequest(BaseModel):
    user: str
    message: str

# ---------------------------
# Endpoints
# ---------------------------
@app.get("/")
def health():
    return {"status": "ok", "message": "GuardRail Wrapper server is running."}

@app.get("/wake")
def wake(background_tasks: BackgroundTasks):
    # Optionally do some warm-up in background; we just no-op.
    background_tasks.add_task(lambda: None)
    return {"status": "ok", "message": "Server warmed up"}

@app.post("/scan")
def scan(req: ScanRequest):
    input_text = req.prompt
    # 1) Get model output (mock or OpenAI)
    if USE_OPENAI:
        try:
            completion = openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": input_text}],
            )
            llm_output = completion.choices[0].message.content or ""
            provider = "openai"
        except Exception:
            llm_output = f"(mock) Answer to: {input_text}"
            provider = "mock"
    else:
        llm_output = f"(mock) Answer to: {input_text}"
        provider = "mock"

    # 2) Guardrails
    pii = redact_pii(llm_output)

    # 3) Persist
    ensure_schema()
    db_exec(
        """
        INSERT INTO logs (ts, provider, input_text, raw_output, redacted_output, flagged, redactions_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(time.time()),
            provider,
            input_text,
            llm_output,
            pii["output"],
            1 if pii["flagged"] else 0,
            json.dumps(pii["redactions"]),
        ),
    )

    # 4) Response
    return {
        "raw_output": llm_output,
        "redacted_output": pii["output"],
        "flagged": pii["flagged"],
        "incidents": [],  # optional per-req incidents list
    }

@app.post("/chat")
def chat(req: ChatRequest):
    input_text = req.message

    if USE_OPENAI:
        try:
            completion = openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": input_text}],
            )
            answer = completion.choices[0].message.content or ""
            provider = "openai"
        except Exception:
            answer = f"(mock) Answer: {input_text}"
            provider = "mock"
    else:
        answer = f"(mock) Answer: {input_text}"
        provider = "mock"

    pii = redact_pii(answer)

    ensure_schema()
    db_exec(
        """
        INSERT INTO logs (ts, provider, input_text, raw_output, redacted_output, flagged, redactions_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(time.time()),
            provider,
            input_text,
            answer,
            pii["output"],
            1 if pii["flagged"] else 0,
            json.dumps(pii["redactions"]),
        ),
    )

    return {
        "answer": pii["output"],
        "flagged": pii["flagged"],
        "redactions": [r.get("type", "other") for r in pii["redactions"]],
    }

@app.get("/metrics")
def metrics():
    ensure_schema()
    total, flagged = db_query("SELECT COUNT(*), SUM(flagged) FROM logs")[0]
    total = total or 0
    flagged = flagged or 0
    return {
        "total_requests": total,
        "flagged_outputs": flagged,
        "flag_rate": (flagged / total) if total else 0.0,
    }

@app.get("/logs")
def get_logs(limit: int = Query(25, ge=1, le=500)):
    ensure_schema()
    try:
        rows = db_query(
            """
            SELECT id, datetime(ts,'unixepoch') as timestamp, provider, flagged, redactions_json
            FROM logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
    except sqlite3.OperationalError:
        rows = []

    out = []
    for r in rows:
        out.append(
            {
                "id": r[0],
                "time": r[1],
                "provider": r[2] or "mock",
                "flagged": bool(r[3]),
                "redactions": [x.get("type", "other") for x in json.loads(r[4] or "[]")],
            }
        )
    return out

@app.get("/incidents")
def incidents(limit: int = 10):
    # For now, reuse logs to simulate "incidents"
    ensure_schema()
    rows = db_query(
        """
        SELECT id, datetime(ts,'unixepoch') as timestamp, provider, flagged, redactions_json
        FROM logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    out = []
    for r in rows:
        out.append(
            {
                "id": r[0],
                "time": r[1],
                "provider": r[2] or "mock",
                "flagged": bool(r[3]),
                "redactions": [x.get("type", "other") for x in json.loads(r[4] or "[]")],
            }
        )
    return out
