"""A /dev/tty stand-in: pipes are not seekable, like a real terminal."""
import builtins
import os
from unittest.mock import patch


def answering(text):
    """Patches open() so /dev/tty reads `text` and records what was written; returns (patcher, written pipe fd)."""
    rin, win = os.pipe(); rout, wout = os.pipe()
    os.write(win, text.encode()); os.close(win)
    real = builtins.open
    def fake(path, mode='r', *args, **kwargs):
        if path != '/dev/tty': return real(path, mode, *args, **kwargs)
        return os.fdopen(os.dup(rin if 'r' in mode else wout), mode, encoding='utf-8')
    return patch('builtins.open', fake), rout, (rin, wout)
