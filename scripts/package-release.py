#!/usr/bin/env python3
# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com
"""Package only a tested binary and the license, never the developer checkout."""
import hashlib, pathlib, shutil, subprocess, sys, tarfile, zipfile

target, version = sys.argv[1:]
windows = target.endswith('windows-msvc')
binary = pathlib.Path('target') / target / 'release' / ('hc.exe' if windows else 'hc')
actual = subprocess.check_output([str(binary), '--version'], text=True).strip()
assert actual == 'hc ' + version, (actual, version)
subprocess.run([str(binary), '--help'], check=True, stdout=subprocess.DEVNULL)
out = pathlib.Path('dist'); out.mkdir(exist_ok=True)
# Raw executables let the native updater avoid an archive extraction dependency.
shutil.copy2(binary, out / ('hc-' + target + ('.exe' if windows else '')))
archive = out / ('hc-' + target + ('.zip' if windows else '.tar.gz'))
if windows:
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        z.write(binary, 'hc.exe'); z.write('LICENSE', 'LICENSE')
else:
    with tarfile.open(archive, 'w:gz') as t:
        t.add(binary, arcname='hc', recursive=False); t.add('LICENSE', arcname='LICENSE', recursive=False)
print(hashlib.sha256(archive.read_bytes()).hexdigest(), archive.name)
