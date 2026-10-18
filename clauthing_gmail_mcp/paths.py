"""Private storage indexed by the server process's actual current directory."""
import hashlib
import os
import re
from pathlib import Path


def config_directory():
    return Path(os.environ.get('XDG_CONFIG_HOME') or Path.home()/'.config')/'clauthing-gmail-mcp'


def data_directory():
    return Path(os.environ.get('XDG_DATA_HOME') or Path.home()/'.local/share')/'clauthing-gmail-mcp'


def project_key(directory=None):
    canonical = str(Path.cwd().resolve() if directory is None else Path(directory).resolve())
    label = re.sub(r'[^A-Za-z0-9_-]+', '-', canonical).strip('-')[-80:] or 'root'
    digest = hashlib.sha256(os.fsencode(canonical)).hexdigest()[:16]
    return f'{label}-{digest}'


def project_directory(directory=None):
    return data_directory()/'projects'/project_key(directory)
