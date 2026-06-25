#!/usr/bin/env python3
"""
CICS (mainframe transaction) Bridge MCP — CSOAI Layer-0 legacy-bridge family.
Parse CICS programs/transactions, map to modern services, govern. Sibling of cobol-bridge-mcp.
Tools: parse_cics · identify_transactions · map_to_modern · govern_cics
"""
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field
from typing import List, Dict, Any
import re

mcp = FastMCP("CICS Bridge", instructions="Bridge IBM CICS mainframe transactions to ONE OS — parse, map, govern.")

# ── SIGIL: every governed action → one signed hash-chained hop (SIGIL_LOG unifies all layers) ──
import hashlib as _hl, time as _t, json as _j, os as _os
_SIGIL_LOG = _os.environ.get("SIGIL_LOG", _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "bridge_sigil.log"))
def _sigil(op, body):
    try:
        prev = ""
        if _os.path.exists(_SIGIL_LOG):
            with open(_SIGIL_LOG) as f:
                ls = f.readlines()
                if ls: prev = _j.loads(ls[-1]).get("digest", "")
        ts = int(_t.time()); dg = _hl.sha256(f"{op}|{ts}|{prev[:8]}|{body}".encode()).hexdigest()[:16]
        _os.makedirs(_os.path.dirname(_SIGIL_LOG), exist_ok=True)
        with open(_SIGIL_LOG, "a") as f: f.write(_j.dumps({"ts": ts, "op": op, "body": body, "prev_digest": prev, "digest": dg}) + "\n")
        return dg
    except Exception: return ""


class CICSParsed(BaseModel):
    exec_commands: List[str] = Field(default_factory=list)
    transactions: List[str] = Field(default_factory=list)
    programs_called: List[str] = Field(default_factory=list)
    uses_commarea: bool = False
    line_count: int = 0


class Governance(BaseModel):
    risk_flags: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    attestable: bool = True
    note: str = ""


@mcp.tool()
def parse_cics(source_code: str) -> CICSParsed:
    """Parse a CICS program: EXEC CICS commands, transaction IDs, LINK/XCTL targets, COMMAREA use."""
    s = source_code
    cmds = re.findall(r"EXEC\s+CICS\s+([A-Z]+)", s, re.I)
    txns = re.findall(r"\bTRANSID\s*\(\s*['\"]?(\w+)", s, re.I) + re.findall(r"\bSTART\s+TRANSID\s*\(\s*['\"]?(\w+)", s, re.I)
    progs = re.findall(r"(?:LINK|XCTL)\s+PROGRAM\s*\(\s*['\"]?(\w+)", s, re.I)
    return CICSParsed(
        exec_commands=sorted(set(c.upper() for c in cmds))[:30],
        transactions=sorted(set(txns))[:30],
        programs_called=sorted(set(progs))[:30],
        uses_commarea=bool(re.search(r"COMMAREA", s, re.I)),
        line_count=len(s.splitlines()),
    )


@mcp.tool()
def identify_transactions(source_code: str) -> Dict[str, Any]:
    """List the CICS transactions + programs this code drives (migration scope)."""
    p = parse_cics(source_code)
    return {"transactions": p.transactions, "programs": p.programs_called,
            "commands": p.exec_commands, "note": "Each EXEC CICS verb maps to a modern transaction-context call."}


@mcp.tool()
def map_to_modern(source_code: str) -> Dict[str, Any]:
    """Map CICS program shape to a modern transactional service skeleton."""
    p = parse_cics(source_code)
    return {"source": "IBM CICS", "target": "modern transactional service",
            "endpoints": p.transactions or ["main"], "calls": p.programs_called,
            "state": "COMMAREA -> request/session context" if p.uses_commarea else "stateless"}


@mcp.tool()
def govern_cics(source_code: str) -> Governance:
    """Governance: transaction integrity + access surface (attestable for CSOAI)."""
    _sigil("G", "cics|govern_cics")
    p = parse_cics(source_code)
    flags = []
    if any(c in p.exec_commands for c in ("SEND", "RECEIVE")) and "RETURN" not in p.exec_commands:
        flags.append("Terminal I/O without explicit RETURN — review transaction boundaries")
    if not p.uses_commarea and p.programs_called:
        flags.append("Inter-program calls without COMMAREA — verify state handling on migration")
    return Governance(risk_flags=flags,
                      frameworks=["IBM CICS TS", "SOX (ITGC)", "PCI-DSS (if cardholder)", "DORA"],
                      note="CSOAI governs the bridge: transaction lineage attestable on the ledger.")


def main():
    mcp.run()


if __name__ == "__main__":
    main()
