import importlib.util,json,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag
class BackupTests(unittest.TestCase):
 def load(self,name,file):
  spec=importlib.util.spec_from_file_location(name,Path(__file__).resolve().parents[1]/'server'/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
 def test_encrypt_roundtrip_and_tamper_rejected(self):
  m=self.load('backup','encrypted_backup.py');key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
  private=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption());public=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
  raw=b'private account snapshot';sealed=m.encrypt(raw,public);self.assertNotIn(raw,sealed);self.assertEqual(m.decrypt(sealed,private),raw)
  import base64
  envelope=json.loads(sealed);data=bytearray(base64.b64decode(envelope['data']));data[-1]^=1;envelope['data']=base64.b64encode(data).decode()
  with self.assertRaises(InvalidTag):m.decrypt(json.dumps(envelope),private)
 def test_retention_uses_file_date_even_if_touched_today(self):
  m=self.load('retention','diagnostic_collector.py')
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);old=p/'2020-01-01.jsonl';old.write_text('{}');new=p/(time.strftime('%Y-%m-%d',time.gmtime())+'.jsonl');new.write_text('{}')
   with patch.object(m,'LOG',p):m.prune()
   self.assertFalse(old.exists());self.assertTrue(new.exists())
