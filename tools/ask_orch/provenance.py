"""Identify the checkout and installed components behind a test report."""

import hashlib
import os
from pathlib import Path
import subprocess

from ask_orch import build_record, manifest


def checkout(root):
    names = build_record.names(root)
    digest = hashlib.sha256()
    for name in names:
        path = Path(root) / name
        if path.is_symlink():
            kind, content = b"link", hashlib.sha256(os.fsencode(os.readlink(path))).digest()
        elif path.is_file():
            kind = b"executable" if path.stat().st_mode & 0o111 else b"file"
            with path.open("rb") as stream:
                content = hashlib.file_digest(stream, "sha256").digest()
        else:
            kind, content = b"missing", b""
        digest.update(os.fsencode(name) + b"\0" + kind + b"\0" + content)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, timeout=10)
    return {"revision": revision.decode().strip(), "sha256": digest.hexdigest(), "files": len(names)}


def agent_sources(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(Path(root).rglob("*.py"))}


# The DUT image's identity, the same in every boot of it -- the startup
# suite's rdinit=/bin/sh boot included, where no module has loaded yet: the
# kernel's build notes, every file in its module tree, the build records of
# what each component was built from (manifest.verify() reads them), and the
# device tree's own record of the kernel build that compiled it.
IMAGE = f'''
RECORDS = {manifest.IMAGE_DIR!r}
DEVICETREE = '/sys/firmware/devicetree/base/' + {manifest.DEVICETREE_PROPERTY!r}
''' + '''
import hashlib, json, pathlib, platform
def digest(path):
    path = pathlib.Path(path)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
def paths(record):
    try:
        return json.loads(record.read_bytes())['paths']
    except (ValueError, KeyError, TypeError):
        return None
def build():
    return {'build': {path.stem: {'sha256': digest(path), 'paths': paths(path)}
                      for path in sorted(pathlib.Path(RECORDS).glob('*.json'))},
            'devicetree': (pathlib.Path(DEVICETREE).read_bytes().rstrip(b'\\0').decode()
                           if pathlib.Path(DEVICETREE).exists() else None)}
def image():
    tree = hashlib.sha256()
    base = pathlib.Path('/lib/modules') / platform.release()
    for path in sorted(p for p in base.rglob('*') if p.is_file() and not p.is_symlink()):
        tree.update(str(path.relative_to(base)).encode() + b'\\0' + bytes.fromhex(digest(path)))
    return {'kernel_notes_sha256': digest('/sys/kernel/notes'), 'modules_sha256': tree.hexdigest(),
            **build()}
'''


def image_script():
    return IMAGE + "print(json.dumps(image()))\n"


def firmware_script(required):
    # Run once on the DUT; only hashes and component identities cross UART.
    return IMAGE + f'''
import shutil
import askd_agent
root = pathlib.Path(askd_agent.__file__).parent
modules = {{}}
for path in sorted(pathlib.Path('/sys/module').iterdir()):
    note = path / 'notes/.note.gnu.build-id'
    version = path / 'srcversion'
    if note.exists() or version.exists():
        modules[path.name] = {{'build_id_note_sha256': digest(note),
                              'srcversion': version.read_text().strip() if version.exists() else None}}
tools = {{name: shutil.which(name) for name in {sorted(required)!r}}}
print(json.dumps({{'kernel': platform.release(), 'kernel_notes_sha256': digest('/sys/kernel/notes'),
                  'image': image(),
                  'agent_sources': {{str(path.relative_to(root)): digest(path) for path in sorted(root.rglob('*.py'))}},
                  'modules': modules, 'binaries': {{name: {{'path': path, 'sha256': digest(path)}}
                                                for name, path in tools.items() if path}},
                  'missing_binaries': [name for name, path in tools.items() if not path]}}))
'''
