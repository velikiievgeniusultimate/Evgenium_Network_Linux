import importlib.util
import io
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import MagicMock, patch


def load(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).resolve().parents[1]/'server'/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class IssuerBoundaryTests(unittest.TestCase):
    def test_public_route_cannot_forward_admin_operation(self):
        collector=load('collector','diagnostic_collector.py')
        for operation in ('device','enroll'):
            handler=object.__new__(collector.Handler)
            body=json.dumps({'operation':'admin-delete-account','id':'a'*24}).encode()
            handler.headers={'Content-Length':str(len(body))};handler.rfile=io.BytesIO(body);handler.reply=MagicMock()
            connection=MagicMock();connection.__enter__.return_value=connection
            connection.makefile.return_value=io.BytesIO(b'{"ok":false}\n')
            with patch.object(collector.socket,'socket',return_value=connection):handler.enroll(operation)
            sent=json.loads(connection.sendall.call_args.args[0]);self.assertEqual(sent['operation'],operation)
            handler.reply.assert_called_once_with(403,{'ok':False})
    def test_admin_operation_requires_root_peer(self):
        issuer=load('issuer','token_issuer.py');handler=object.__new__(issuer.Handler)
        handler.connection=MagicMock();handler.connection.getsockopt.return_value=struct.pack('3i',123,1000,1000)
        handler.rfile=io.BytesIO(json.dumps({'operation':'admin-delete-account','id':'a'*24}).encode()+b'\n');handler.wfile=io.BytesIO()
        with patch.object(issuer,'delete_account') as delete,patch.object(issuer.time,'sleep'):
            handler.handle();delete.assert_not_called()
        self.assertFalse(json.loads(handler.wfile.getvalue())['ok'])
