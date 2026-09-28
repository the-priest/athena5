#!/usr/bin/env python3
"""Athena v7.8 smoke test.

Fast and fully OFFLINE by default — it exercises module loading, the tool
bridge, the settings layer, the provider registry and prompt assembly without
touching the network.  Pass --live to additionally hit each enabled provider's
``GET /models`` endpoint (needs a key and connectivity).

    python3 tests/smoke.py          # offline
    python3 tests/smoke.py --live   # + live model discovery
"""
from __future__ import annotations

import argparse
import json
import py_compile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_PASS: list[str] = []
_FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (_PASS if cond else _FAIL).append(name)
    mark = "✓" if cond else "✗"
    extra = f"  ({detail})" if (detail and not cond) else ""
    print(f"  {mark} {name}{extra}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true",
                    help="also query provider /models endpoints")
    args = ap.parse_args()

    print("── compile ─────────────────────────────────────────────")
    targets = list(ROOT.glob("*.py")) + list((ROOT / "athena_ext").glob("*.py"))
    try:
        for p in targets:
            py_compile.compile(str(p), doraise=True)
        check(f"compile {len(targets)} python files", True)
    except py_compile.PyCompileError as e:
        check("compile all python files", False, str(e))
        return _summary()

    print("── import ──────────────────────────────────────────────")
    import athena
    from athena_ext import settings as S
    from athena_ext import providers as P

    check("EXT_MODULES non-empty", len(athena.EXT_MODULES) >= 25,
          f"{len(athena.EXT_MODULES)}")
    for n in athena.EXT_MODULES:
        athena._ext(n)
    st = athena.ext_status()
    bad = {k: v for k, v in st.items() if v != "loaded"}
    check(f"all {len(st)} athena_ext modules load", not bad, str(bad))
    check("tool bridge merged into dispatch (>=60)",
          len(athena.PURE_TOOL_DISPATCH) >= 60,
          f"{len(athena.PURE_TOOL_DISPATCH)}")
    check("bridge spec attached to prompt spec",
          "exploit_build" in athena.PURE_TOOL_SPEC)

    print("── settings ────────────────────────────────────────────")
    orig = S.PATH.read_bytes() if S.PATH.exists() else None
    try:
        S.save(dict(S.DEFAULTS))
        check("settings save/load roundtrip", S.get("temperature") == 0.2)
        S.set("temperature", 0.55)
        check("settings set persists", abs(S.get("temperature") - 0.55) < 1e-9)
        check("settings describe renders", "temperature" in S.describe())
    finally:
        if orig is not None:
            S.PATH.write_bytes(orig)
        elif S.PATH.exists():
            S.PATH.unlink()

    print("── providers ───────────────────────────────────────────")
    check("provider registry has many providers", len(P.REGISTRY) >= 10,
          f"{len(P.REGISTRY)}")
    check("rank puts a capable model first",
          P.rank_models(["allam-2-7b", "qwen/qwen3.8-27b",
                         "openai/gpt-oss-120b"])[0].startswith("qwen"))
    check("filter drops audio/tts models",
          not P.chat_capable("whisper-large-v3")
          and not P.chat_capable("canopylabs/orpheus-v1-english"))
    check("filter keeps chat models",
          P.chat_capable("llama-3.3-70b-versatile"))
    chain = P.build_chain(S.load(), live=False)
    check("build_chain returns (model, name, provider) tuples",
          bool(chain) and all(len(r) == 3 for r in chain), str(chain[:2]))

    print("── tool bridge ─────────────────────────────────────────")
    out, err = athena.run_pure_tool(None, "parse_output", json.dumps(
        {"tool": "nmap",
         "raw": "22/tcp open ssh OpenSSH 8.2p1\n80/tcp open http nginx 1.18.0"}))
    check("bridge parse_output", err is None and bool(out), str(err))
    out, err = athena.run_pure_tool(None, "exploit_encode", json.dumps(
        {"payload": "<script>alert(1)</script>", "scheme": "url"}))
    check("bridge exploit_encode", err is None and bool(out), str(err))
    out, err = athena.run_pure_tool(None, "exploit_fingerprint", json.dumps(
        {"headers": "Server: nginx/1.18.0", "body": ""}))
    check("bridge exploit_fingerprint", err is None and bool(out), str(err))
    _out, err = athena.run_pure_tool(None, "does_not_exist", "{}")
    check("unknown tool returns error", err is not None)
    _out, err = athena.run_pure_tool(None, "parse_output", "{bad json")
    check("malformed [ARGS] returns error", err is not None)

    print("── prompt ──────────────────────────────────────────────")
    ptt = athena.PTT(goal="smoke test")
    p1 = athena.build_system_prompt("recon", {"ip": "10.0.0.5"},
                                    ptt, None, "10.0.0.1", turn_no=1)
    p5 = athena.build_system_prompt("recon", {"ip": "10.0.0.5"},
                                    ptt, None, "10.0.0.1", turn_no=5)
    spec_marker = "ATHENA ENGINES (in-process"
    check("turn-1 prompt carries the engine spec", spec_marker in p1)
    check("turn-5 prompt drops the engine spec (token savings)",
          spec_marker not in p5)
    check("ELITE LOOP always present", "ELITE LOOP" in p1 and "ELITE LOOP" in p5)
    check("turn-1 prompt larger than turn-5", len(p1) > len(p5),
          f"{len(p1)} vs {len(p5)}")

    if args.live:
        print("── live discovery ──────────────────────────────────────")
        d = S.load()
        enabled = [p for p in P.ORDER if P.is_enabled(p, d)]
        check("at least one provider configured", bool(enabled), str(enabled))
        for p in enabled:
            got = P.list_models(p, timeout=8, use_cache=False, settings=d)
            check(f"live /models [{p}]", got["ok"],
                  f"{got['error']} ({len(got['models'])} fallback)")

    return _summary()


def _summary() -> int:
    print("\n════════════════════════════════════════════════════════")
    print(f"  {len(_PASS)} passed, {len(_FAIL)} failed")
    if _FAIL:
        print("  failures: " + ", ".join(_FAIL))
    print("════════════════════════════════════════════════════════")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
