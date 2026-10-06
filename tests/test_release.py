import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ReleaseTests(unittest.TestCase):
    def test_both_channels_have_valid_identical_portable_payload(self):
        version=(ROOT/'VERSION').read_text().strip()
        archive=ROOT/'dist'/f'vpn-manager-{version}.tar.gz'
        blob=archive.read_bytes()
        digest=hashlib.sha256(blob).hexdigest()
        for channel in ('stable','testing'):
            manifest=json.loads((ROOT/'update'/f'{channel}.json').read_text())
            self.assertEqual(manifest['channel'],channel)
            self.assertEqual(manifest['version'],version)
            self.assertEqual(manifest['sha256'],digest)
            self.assertEqual(manifest['xray_version'],'26.7.28')
            self.assertEqual(manifest['url'],f'https://raw.githubusercontent.com/velikiievgeniusultimate/Evgenium_Network_Linux/main/dist/{archive.name}')
        with tarfile.open(fileobj=io.BytesIO(blob),mode='r:gz') as tf:
            members=tf.getmembers()
            self.assertEqual([m.name for m in members],['vpnctl.py','vpnadmin.py','VERSION'])
            for member in members:
                self.assertTrue(member.isfile())
                expected=(ROOT/'VERSION') if member.name=='VERSION' else ROOT/'src'/member.name
                self.assertEqual(tf.extractfile(member).read(),expected.read_bytes())
                self.assertEqual(member.mode,0o644 if member.name=='VERSION' else 0o755)

    def test_package_selftest_and_compilation_without_installation(self):
        subprocess.run([sys.executable,str(ROOT/'src/vpnctl.py'),'--self-test'],check=True)
        for filename in ('vpnctl.py','vpnadmin.py'):
            compile((ROOT/'src'/filename).read_text(),filename,'exec')

if __name__=='__main__':
    unittest.main()
