# main.py
from fastapi import FastAPI, Query, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any
import re, os, json, time, sqlite3

# --- Optional OpenAI (defaults to mock echo) ---
from dotenv import load_dotenv
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
PROVIDER = os.getenv("PROVIDER", "mock").lower()  # "openai" or "mock"
USE_OPENAI = bool(OPENAI_API_KEY) and PROVIDER == "openai"
if USE_OPENAI:
    try:
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_API_KEY)
    except Exception:
        USE_OPENAI = False  # fall back to mock if package missing

# --- FastAPI app + CORS ---
app = FastAPI(title="GuardRail Wrapper (MVP)")

# Explicitly declare the allowed origins for your frontend
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Explicit OPTIONS handler (belt and suspenders)
@app.options("/chat")
def options_chat():
    return Response(status_code=204)

# --- SQLite setup ---
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
        rows = cur.fetchall()
        return rows
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

# --- PII redaction helpers ---
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

    flagged = len(redactions) > 0
    return {
        "output": out,
        "flagged": flagged,
        "redactions": redactions,
        "checks_ran": ["pii_redaction_v1"],
    }

# --- Models ---
class ChatRequest(BaseModel):
    prompt: str

# --- Routes ---
@app.get("/")
def health():
    return {"status": "ok", "message": "GuardRail Wrapper server is running."}

@app.post("/chat")
def chat(req: ChatRequest):
    input_text = req.prompt

    # 1) Get model output (mock or OpenAI)
    if USE_OPENAI:
        try:
            # Replace with your preferred endpoint/model
            completion = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": input_text}],
            )
            llm_output = completion.choices[0].message.content or ""
            provider = "openai"
        except Exception as e:
            # fall back to mock if API fails (quota, etc.)
            llm_output = f"(mock) Answer to: {input_text}"
            provider = "mock"
    else:
        llm_output = f"(mock) Answer to: {input_text}"
        provider = "mock"

    # 2) Apply guardrails/redactions to the LLM output
    pii = redact_pii(llm_output)

    # 3) Persist the event
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

    # 4) Return structured result
    return {
        "input_prompt": input_text,
        "raw_output": llm_output,
        "output_message": pii["output"],
        "flagged": pii["flagged"],
        "redactions": pii["redactions"],
        "checks_ran": pii["checks_ran"],
    }

@app.get("/metrics")
def metrics():
    ensure_schema()
    row = db_query("SELECT COUNT(*), SUM(flagged) FROM logs")[0]
    total = row[0] or 0
    flagged = row[1] or 0
    flag_rate = (flagged / total) if total > 0 else 0.0
    return {
        "total_requests": total,
        "flagged_count": flagged,
        "flag_rate": flag_rate,
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
                "timestamp": r[1],
                "provider": r[2] or "mock",
                "flagged": bool(r[3]),
                "redactions": json.loads(r[4] or "[]"),
            }
        )
    return out
