"""
basilisk_ext — a sidecar for Basilisk (oracle5).

Design contract (read this before wiring):

  * This package NEVER imports basilisk.py / basilisk_core.py / basilisk_persona.py.
    It depends only on the Python stdlib plus two callables you inject at
    boot.  That is what keeps your core authoritative and lets the whole
    thing be deleted with zero residue.

  * Everything is OFF until enabled in settings.  Absent package or absent
    keys => every hook is a no-op and Basilisk behaves exactly as it does today.

  * Nothing here writes outside ~/.local/share/basilisk/ext/.  No system files,
    no system units, no root.  The optional daemon is `systemd --user`.

Boot wiring (host side, see WIRING.md):

    from basilisk_ext import extman
    extman.init(
        settings   = self.settings,          # your dict
        data_dir   = "~/.local/share/basilisk",  # your DATA_DIR
        complete_fn= self._ext_complete,     # (system:str, user:str) -> str
        embed_fn   = None,                   # optional (list[str]) -> list[list[float]]
    )

Then four optional hook points (each a no-op if the package is absent):

    full     = extman.inject_memory(full)            # before stream_chat
    extman.record_turn(user_text, assistant_text)    # after a turn settles
    dispatch.update(extman.extra_tools(self))        # in _execute_tool_calls
    verdict  = extman.foresight(command)             # before an action runs
"""

from . import extman  # noqa: F401

__all__ = ["extman"]
__version__ = "0.1.0"
