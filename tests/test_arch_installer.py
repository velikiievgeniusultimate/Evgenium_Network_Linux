"""Run the real shell dependency installer with an isolated package-manager fixture."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FUNCTION = (ROOT / 'install.sh').read_text().split('# BEGIN ARCH DEPENDENCY INSTALL\n')[1].split('# END ARCH DEPENDENCY INSTALL')[0]


class ArchInstallerTests(unittest.TestCase):
    def execute(self, *, custom_db=False, official_db=True, returncode=0):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            bins = folder / 'bin'; bins.mkdir()
            db = folder / 'database with spaces'; (db / 'sync').mkdir(parents=True)
            for repo, exists in [('core', official_db), ('extra', True), ('openai-chatgpt', custom_db)]:
                if exists: (db / 'sync' / (repo + '.db')).touch()
            config = folder / 'resolved.conf'
            original = f'''[options]
DBPath = {db}/
Architecture = x86_64
IgnorePkg = special-package
SigLevel = PackageRequired
SigLevel = PackageTrustedOnly
[core]
Server = https://mirror.example/core/os/x86_64
[openai-chatgpt]
SigLevel = PackageRequired
Server = https://custom.example/repo
[extra]
Server = https://mirror.example/extra/os/x86_64
'''
            config.write_text(original)
            scripts = {
                'pacman-conf': '#!/bin/sh\nif [ "$1" = DBPath ]; then printf "%s\\n" "$FIXTURE_DB"; else cat "$FIXTURE_CONF"; fi\n',
                'sudo': '#!/bin/sh\nexec "$@"\n',
                'pacman': '''#!/usr/bin/env python3
import json,os,pathlib,sys
p=pathlib.Path(sys.argv[2])
pathlib.Path(os.environ['FIXTURE_OUTPUT']).write_text(json.dumps({'argv':sys.argv[1:],'config':p.read_text(),'path':str(p)}))
sys.exit(int(os.environ['FIXTURE_RC']))
''',
            }
            for name, script in scripts.items():
                (bins / name).write_text(script); (bins / name).chmod(0o755)
            output = folder / 'output.json'
            env = dict(os.environ, PATH=str(bins)+os.pathsep+os.environ['PATH'],
                       FIXTURE_DB=str(db), FIXTURE_CONF=str(config), FIXTURE_OUTPUT=str(output),
                       FIXTURE_RC=str(returncode), TMPDIR=str(folder))
            script = 'set -Eeuo pipefail\nwarn() { echo "$*" >&2; }; die() { echo "$*" >&2; exit 1; };\n'+FUNCTION+'\narch_install_dependencies strongswan conntrack-tools\n'
            cp = subprocess.run(['bash', '-c', script], env=env, text=True, capture_output=True)
            self.assertEqual(config.read_text(), original)
            self.assertFalse(list(folder.glob('tmp.*')), 'temporary config must be removed on success/failure')
            return cp, json.loads(output.read_text()) if output.exists() else None

    def test_missing_custom_database_is_skipped_without_changing_other_settings(self):
        cp, result = self.execute()
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn('openai-chatgpt', cp.stderr)
        self.assertNotIn('[openai-chatgpt]', result['config'])
        self.assertNotIn('custom.example', result['config'])
        for text in ('[core]', '[extra]', 'IgnorePkg = special-package', 'SigLevel = PackageRequired', 'SigLevel = PackageTrustedOnly', 'https://mirror.example/extra/os/x86_64'):
            self.assertIn(text, result['config'])
        self.assertEqual(result['argv'][2:], ['-S', '--needed', '--noconfirm', 'strongswan', 'conntrack-tools'])

    def test_usable_custom_repository_is_preserved(self):
        cp, result = self.execute(custom_db=True)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn('[openai-chatgpt]', result['config'])
        self.assertEqual(cp.stderr, '')

    def test_missing_official_database_stops_before_transaction(self):
        cp, result = self.execute(official_db=False)
        self.assertNotEqual(cp.returncode, 0)
        self.assertIsNone(result)
        self.assertIn('официального репозитория core', cp.stderr)

    def test_transaction_failure_is_not_reported_as_success(self):
        cp, result = self.execute(returncode=37)
        self.assertEqual(cp.returncode, 37)
        self.assertIsNotNone(result)


if __name__ == '__main__': unittest.main()
