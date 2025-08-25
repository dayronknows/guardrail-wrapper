# main.py
from fastapi import FastAPI, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import re, os, json, time, sqlite3

# ---------- Models ----------
class Incident(BaseModel):
    id: int
    time: str           # ISO-like string from SQLite datetime
    provider: str
    flagged: bool
    redactions: List[str]

INCIDENTS: List[Incident] = []  # in-memory cache for demo (derived from DB)

class ChatRequest(BaseModel):
    # allow either {prompt} OR {user, message}
    prompt: Optional[str] = None
    user: Optional[str] = None
    message: Optional[str] = None

class ChatReply(BaseModel):
    answer: str
    flagged: bool
    redactions: List[str]

class ScanRequest(BaseModel):
    prompt: str

class ScanResponse(BaseModel):
    raw_output: str
    redacted_output: str
    flagged: bool
    incidents: List[Incident]

# ---------- OpenAI (optional, defaults to mock) ----------
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
        USE_OPENAI = False

# ---------- FastAPI + CORS ----------
app = FastAPI(title="GuardRail Wrapper (MVP)")

ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    # add your deployed UI domain(s):
    "https://guardrail-admin.vercel.app",
    # add Squarespace page host if you embed:
    # "https://<your-squarespace-domain>"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)

@app.options("/{rest_of_path:path}")
def options_catchall(rest_of_path: str) -> Response:
    return Response(status_code=204)

# ---------- SQLite ----------
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

# ---------- Guardrails (PII redaction) ----------
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

# ---------- Helpers ----------
def call_llm(input_text: str) -> (str, str):
    """Return (raw_output, provider). Uses OpenAI if configured else mock."""
    if USE_OPENAI:
        try:
            completion = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": input_text}],
            )
            return completion.choices[0].message.content or "", "openai"
        except Exception:
            pass
    return f"(mock) Answer to: {input_text}", "mock"

def persist_and_emit(raw: str, redacted: Dict[str, Any], provider: str, input_text: str):
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
            raw,
            redacted["output"],
            1 if redacted["flagged"] else 0,
            json.dumps(redacted["redactions"]),
        ),
    )

# ---------- Routes ----------
@app.get("/")
def health():
    return {"status": "ok", "message": "GuardRail Wrapper server is running."}

@app.get("/metrics")
def metrics():
    ensure_schema()
    row = db_query("SELECT COUNT(*), SUM(flagged) FROM logs")[0]
    total = row[0] or 0
    flagged = row[1] or 0
    flag_rate = (flagged / total) if total > 0 else 0.0
    return {
        "total_requests": total,
        "flagged_outputs": flagged,
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

@app.get("/incidents", response_model=List[Incident])
def get_incidents(limit: int = 10):
    # Build incidents from DB (newest first)
    ensure_schema()
    rows = db_query(
        """
        SELECT id, datetime(ts,'unixepoch') as timestamp, provider, flagged, redactions_json
        FROM logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )
    items: List[Incident] = []
    for r in rows:
        redacts = [rd.get("type", "other") for rd in json.loads(r[4] or "[]")]
        items.append(
            Incident(
                id=int(r[0]),
                time=str(r[1]),
                provider=str(r[2] or "mock"),
                flagged=bool(r[3]),
                redactions=redacts,
            )
        )
    return items

@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest):
    input_text = req.prompt.strip()
    raw, provider = call_llm(input_text)
    pii = redact_pii(raw)
    persist_and_emit(raw, pii, provider, input_text)

    # Build incidents list (last 10)
    recent = get_incidents(limit=10)
    return ScanResponse(
        raw_output=raw,
        redacted_output=pii["output"],
        flagged=pii["flagged"],
        incidents=recent
    )

@app.post("/chat", response_model=ChatReply)
def chat(req: ChatRequest):
    # Accept either {prompt} or {user,message}
    input_text = (req.prompt or req.message or "").strip()
    if not input_text:
        # still return 200 with a friendly message (less brittle than 422)
        return ChatReply(answer="(empty message)", flagged=False, redactions=[])

    raw, provider = call_llm(input_text)
    pii = redact_pii(raw)
    persist_and_emit(raw, pii, provider, input_text)

    # Adapt to ChatReply shape expected by the UI
    redaction_types = [r.get("type", "other") for r in pii["redactions"]]
    return ChatReply(
        answer=pii["output"],
        flagged=pii["flagged"],
        redactions=redaction_types
    )
