# athena_ext — "smart" subsystems ported from Basilisk into Athena.
#
# Each module here is self-contained (stdlib-only) and imported lazily by
# athena.py so a missing/broken module degrades gracefully instead of
# killing the agent at startup.
#
#   memory     persistent cross-session recall (SQLite)
#   oracle     out-of-band canary + verified-exploitation ledger
#   zdayfind   variant-analysis source scanner (Project-Zero style SAST)
#   codescan   SAST / SCA / secrets tool orchestration + result parsers
#   headroom   tool-output / context compression (token savings)
#   foresight  destructive-op risk assessment + undo hints
#   sandbox    bubblewrap isolation primitive + capability report

__all__ = [
    "memory", "oracle", "zdayfind", "codescan",
    "headroom", "foresight", "sandbox",
]

__version__ = "1.0.0"
