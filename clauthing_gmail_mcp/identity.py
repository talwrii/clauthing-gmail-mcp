"""Create a persistent, initially unprivileged MCP identity on first launch."""
import fcntl
import os
import tempfile
from pathlib import Path

from .store import Store


def ensure_identity(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    path = directory/'client.token'
    fd = os.open(directory/'identity.lock', os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if path.exists():
            return path
        store = Store(directory)
        temporary = None
        try:
            identity = store.client_add('mcp')
            fd, temporary = tempfile.mkstemp(dir=directory, prefix='.client-')
            with os.fdopen(fd, 'w') as target:
                target.write(identity['token'] + '\n')
            os.replace(temporary, path)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
            store.close()
    return path
