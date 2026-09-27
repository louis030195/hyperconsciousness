# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com
"""Exercise installer publication boundaries with local, non-network fixtures."""
import hashlib, io, os, pathlib, subprocess, tarfile, tempfile, unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'install.sh'

class Install(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.bin = self.root/'commands'; self.bin.mkdir()
        self.dest = self.root/'installed'; self.dest.mkdir()
        self.fixture = self.root/'release'; self.fixture.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'], HC_INSTALL_DIR=str(self.dest), HC_VERSION='v0.1.0-alpha.5', FIXTURE=str(self.fixture))
        self.command('uname', '#!/bin/sh\ncase "$1" in -s) echo Darwin;; -m) echo arm64;; esac\n')
        self.command('curl', '''#!/bin/sh
out=; url=
while [ "$#" -gt 0 ]; do
 case "$1" in -o) out=$2; shift;; https://*) url=$1;; esac
 shift
done
if [ -z "$out" ]; then printf '[{"tag_name": "v0.1.0-alpha.5"}]\n'; else cp "$FIXTURE/${url##*/}" "$out"; fi
''')
    def command(self, name, text):
        p=self.bin/name; p.write_text(text); p.chmod(0o755)
    def package(self, version='0.1.0-alpha.5', extra=None):
        p=self.fixture/'hc-aarch64-apple-darwin.tar.gz'
        with tarfile.open(p, 'w:gz') as t:
            for name, data in [('hc', f'#!/bin/sh\necho "hc {version}"\n'.encode()), ('LICENSE', b'MIT')]+([] if extra is None else [extra]):
                info=tarfile.TarInfo(name); info.size=len(data); info.mode=0o755
                t.addfile(info, io.BytesIO(data))
        (self.fixture/'SHA256SUMS').write_text(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n')
    def run_installer(self):
        return subprocess.run(['sh', str(SCRIPT)], env=self.env, capture_output=True, text=True, timeout=10)
    def test_verified_install_and_repeat_leave_unrelated_files(self):
        self.package(); (self.dest/'other').write_text('keep')
        for _ in range(2): self.assertEqual(self.run_installer().returncode, 0)
        self.assertEqual((self.dest/'other').read_text(), 'keep')
        self.assertFalse((self.root/'.brain').exists())
        self.assertEqual(subprocess.check_output([str(self.dest/'hc'),'--version'],text=True).strip(),'hc 0.1.0-alpha.5')
    def test_bad_checksum_preserves_existing_binary(self):
        self.package(); (self.dest/'hc').write_text('old')
        (self.fixture/'SHA256SUMS').write_text('0'*64+'  hc-aarch64-apple-darwin.tar.gz\n')
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertEqual((self.dest/'hc').read_text(),'old')
    def test_version_mismatch_and_traversal_do_not_install(self):
        for kwargs in [dict(version='0.0.0'),dict(extra=('../escaped',b'no'))]:
            self.package(**kwargs)
            self.assertNotEqual(self.run_installer().returncode,0)
            self.assertFalse((self.dest/'hc').exists())
            self.assertFalse((self.root/'escaped').exists())
    def test_symlink_and_unsupported_platform_do_not_overwrite(self):
        self.package(); other=self.root/'other';other.write_text('keep')
        (self.dest/'hc').symlink_to(other)
        self.assertNotEqual(self.run_installer().returncode,0)
        self.assertEqual(other.read_text(),'keep')
        self.command('uname','#!/bin/sh\necho unsupported\n')
        self.assertNotEqual(self.run_installer().returncode,0)
    def test_discovers_alpha_release_and_rejects_invalid_version(self):
        self.package(); self.env.pop('HC_VERSION')
        self.assertEqual(self.run_installer().returncode,0)
        self.env['HC_VERSION']='../../bad'
        self.assertNotEqual(self.run_installer().returncode,0)

if __name__ == '__main__': unittest.main()
