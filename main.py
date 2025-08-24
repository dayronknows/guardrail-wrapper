# main.py
from __future__ import annotations

import os
import re
import json
import time
import sqlite3
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Query, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# -----------------------------------------------------------------------------
# Environment / Provider
# -----------------------------------------------------------------------------
load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
PROVIDER = os.getenv("PROVIDER", "mock").lower()  # "openai" or "mock"
USE_OPENAI = bool(OPENAI_API_KEY) and PROVIDER == "openai"

client = None
if USE_OPENAI:
    try:
        from openai import OpenAI  # openai>=1.x
        client = OpenAI(api_key=OPENAI_API_KEY)
    except Exception:
        USE_OPENAI = False  # fall back to mock if import or init fails

# -----------------------------------------------------------------------------
# FastAPI + CORS
# -----------------------------------------------------------------------------
app = FastAPI(title="GuardRail Wrapper (MVP)")

# You can also make this env-driven: ALLOWED_ORIGINS="https://foo,https://bar"
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://guardrail-admin.vercel.app",  # your Vercel frontend
    "dayronknows.me"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Optional catch‑all OPTIONS (extra safety for strict browsers/CDNs)
@app.options("/{rest_of_path:path}")
def options_catchall(rest_of_path: str) -> Response:
    return Response(status_code=204)

# -----------------------------------------------------------------------------
# SQLite helpers
# -----------------------------------------------------------------------------
DB_PATH = os.getenv("DB_PATH", "guardrail.db")


def db_exec(sql: str, params: tuple = ()) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def db_query(sql: str, params: tuple = ()) -> List[tuple]:
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur.fetchall()
    finally:
        conn.close()


def ensure_schema() -> None:
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

# -----------------------------------------------------------------------------
# PII redaction
# -----------------------------------------------------------------------------
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


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


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class IncidentModel(BaseModel):
    id: int
    time: str  # ISO-ish string
    provider: str
    flagged: bool
    redactions: List[str]


class ScanRequest(BaseModel):
    prompt: str


class ScanResponse(BaseModel):
    raw_output: str
    redacted_output: str
    flagged: bool
    incidents: List[IncidentModel]


class ChatIn(BaseModel):
    user: str
    message: str


class ChatOut(BaseModel):
    answer: str
    flagged: bool
    redactions: List[str]

class ChatRequest(BaseModel):
    # Accept either new or old payloads
    prompt: Optional[str] = None
    message: Optional[str] = None
    user: Optional[str] = None


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def run_model(user_input: str) -> Dict[str, str]:
    """Return {'output': <model_output>, 'provider': 'openai'|'mock'}."""
    if USE_OPENAI and client:
        try:
            comp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": user_input}],
            )
            return {
                "output": (comp.choices[0].message.content or "").strip(),
                "provider": "openai",
            }
        except Exception:
            pass
    return {"output": f"(mock) Answer to: {user_input}", "provider": "mock"}


def make_incident_row(
    row: tuple,
) -> IncidentModel:
    # rows from logs: id, ts, provider, flagged, redactions_json
    redactions = [d.get("type", "other") for d in json.loads(row[4] or "[]")]
    return IncidentModel(
        id=row[0],
        time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[1] or 0)),
        provider=row[2] or "mock",
        flagged=bool(row[3]),
        redactions=redactions,
    )


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.get("/")
def health():
    return {"status": "ok", "message": "GuardRail Wrapper server is running."}


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest):
    """Used by the 'Prompt Tester' in your UI."""
    ensure_schema()

    # 1) Model
    model = run_model(req.prompt)
    raw = model["output"]
    provider = model["provider"]

    # 2) Guardrails
    pii = redact_pii(raw)

    # 3) Persist
    db_exec(
        """
        INSERT INTO logs (ts, provider, input_text, raw_output, redacted_output, flagged, redactions_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(time.time()),
            provider,
            req.prompt,
            raw,
            pii["output"],
            1 if pii["flagged"] else 0,
            json.dumps(pii["redactions"]),
        ),
    )

    # Return newest flagged incidents (same table), limited to a few
    rows = db_query(
        """
        SELECT id, ts, provider, flagged, redactions_json
        FROM logs
        ORDER BY id DESC
        LIMIT 10
        """
    )
    incidents = [make_incident_row(r) for r in rows if r[3]]  # only flagged

    return ScanResponse(
        raw_output=raw,
        redacted_output=pii["output"],
        flagged=pii["flagged"],
        incidents=incidents,
    )


@app.post("/chat")
def chat(req: ChatRequest):
    # normalize the text
    input_text = (req.prompt or req.message or "").strip()
    if not input_text:
        raise HTTPException(status_code=422, detail={"type": "missing", "loc": ["body","prompt|message"]})

    # 1) Get model output (mock or OpenAI)
    if USE_OPENAI:
        try:
            completion = client.chat.completions.create(
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

    # 4) Response (keeps the existing UI happy)
    return {
        "answer": pii["output"],
        "flagged": pii["flagged"],
        "redactions": [r.get("type","other") for r in pii["redactions"]],
    }


@app.get("/metrics")
def metrics():
    """UI expects: total_requests, flagged_outputs, flag_rate."""
    ensure_schema()
    row = db_query("SELECT COUNT(*), SUM(flagged) FROM logs")[0]
    total = int(row[0] or 0)
    flagged = int(row[1] or 0)
    rate = (flagged / total) if total > 0 else 0.0
    return {
        "total_requests": total,
        "flagged_outputs": flagged,
        "flag_rate": rate,
    }


@app.get("/logs")
def get_logs(limit: int = Query(25, ge=1, le=500)):
    ensure_schema()
    try:
        rows = db_query(
            """
            SELECT id, ts, provider, flagged, redactions_json
            FROM logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
    except sqlite3.OperationalError:
        rows = []

    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "id": r[0],
                "timestamp": time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(r[1] or 0)
                ),
                "provider": r[2] or "mock",
                "flagged": bool(r[3]),
                "redactions": json.loads(r[4] or "[]"),
            }
        )
    return out


@app.get("/incidents", response_model=List[IncidentModel])
def get_incidents(limit: int = Query(10, ge=1, le=200)):
    """Recent incidents view; we surface flagged rows (newest first)."""
    ensure_schema()
    rows = db_query(
        """
        SELECT id, ts, provider, flagged, redactions_json
        FROM logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    return [make_incident_row(r) for r in rows if r[3]]