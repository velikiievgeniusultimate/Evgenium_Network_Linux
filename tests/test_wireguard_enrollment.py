"""Token boundary, durable enrollment/revocation and peer ownership checks."""
import base64
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]


def load():
    spec = importlib.util.spec_from_file_location('wg_issuer_test', ROOT/'server/token_issuer.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def key(number):
    return base64.b64encode(bytes([number])*32).decode()


class WireGuardEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.i = load(); self.i.ROOT = Path(self.tmp.name)/'accounts'
        self.cfg = {'interface': 'evg-clients', 'subnet': '10.78.0.0/24', 'public_key': key(90), 'endpoint': '195.209.211.163:51820'}
        self.i.wireguard.CONFIG = Path(self.tmp.name)/'config.json'
        self.i.write_json(self.i.wireguard.CONFIG, self.cfg)
        self.peers = {}
        def command(args):
            if args[1:4] == ['show', 'evg-clients', 'peers']:
                return '\n'.join(self.peers)
            self.assertEqual(args[:4], ['wg', 'set', 'evg-clients', 'peer'])
            if args[5] == 'remove':
                self.peers.pop(args[4], None)
            else:
                self.assertEqual(args[5], 'allowed-ips')
                # Enrollment must already exist durably before kernel mutation.
                durable = [d for a in self.i.accounts().values() for d in a['devices'].values() if d.get('public_key') == args[4]]
                self.assertEqual(len(durable), 1)
                self.peers[args[4]] = args[6]
            return ''
        self.command = patch.object(self.i.wireguard, 'command', side_effect=command).start()
        self.addCleanup(patch.stopall)
        self.token = self.i.issue('First'); self.account = next(iter(self.i.accounts()))
        self.other = self.i.issue('Other')

    def request(self, number=1, **values):
        return {'operation': 'wireguard-enroll', 'token': self.token, 'device': f'{number:032x}', 'public_key': key(number), **values}

    def test_one_token_multiple_devices_and_idempotent_same_key(self):
        first = self.i.enroll_wireguard(self.request(1))
        second = self.i.enroll_wireguard(self.request(2, name='Телефон'))
        again = self.i.enroll_wireguard(self.request(1))
        self.assertEqual(first, again)
        self.assertEqual(first['account'], second['account'])
        self.assertEqual(first['device_name'], 'Устройство-1')
        self.assertEqual(second['device_name'], 'Телефон')
        self.assertEqual(second['device_number'], 2)
        self.assertEqual(first['allowed_ips'], ['0.0.0.0/0', '::/0'])
        self.assertNotEqual(first['address'], second['address'])
        self.assertEqual(len(self.peers), 2)
        self.assertNotIn(self.token, (self.i.ROOT/'accounts.json').read_text())
        self.assertNotIn('private', json.dumps(first))
        self.assertEqual((self.i.ROOT/'accounts.json').stat().st_mode & 0o777, 0o600)

    def test_optional_empty_or_whitespace_name_uses_server_default(self):
        first = self.i.enroll_wireguard(self.request(1, name=''))
        second = self.i.enroll_wireguard(self.request(2, name='  \t\n'))
        self.assertEqual(first['device_name'], 'Устройство-1')
        self.assertEqual(second['device_name'], 'Устройство-2')
        self.assertEqual(len(self.peers), 2)
        self.i.enroll_wireguard(self.request(1, name='Телефон'))
        self.assertEqual(self.i.enroll_wireguard(self.request(1, name=''))['device_name'], 'Телефон')

    def test_optional_name_rejects_non_string_before_mutation(self):
        for name in (None, 0, False, [], {}):
            with self.assertRaisesRegex(ValueError, 'invalid_device_name'):
                self.i.enroll_wireguard(self.request(name=name))
        self.command.assert_not_called()
        self.assertEqual(self.i.accounts()[self.account]['devices'], {})

    def test_twelve_revoked_devices_allow_new_device_with_monotonic_number(self):
        for number in range(1, 13):
            self.i.enroll_wireguard(self.request(number))
            self.i.revoke_device(self.account, f'{number:032x}')
        profile = self.i.enroll_wireguard(self.request(13))
        self.assertEqual(profile['device_number'], 13)
        self.assertEqual(profile['device_name'], 'Устройство-13')
        account = self.i.accounts()[self.account]
        self.assertEqual(len(account['devices']), 13)
        self.assertEqual(len(account['device_names']), 13)
        self.assertEqual(account['next_device_number'], 14)
        self.assertEqual(self.i.active_device_count(account), 1)
        self.assertEqual(len(self.peers), 1)
        # A retired ID cannot be revived just because it no longer occupies a slot.
        with self.assertRaisesRegex(PermissionError, 'device_disabled'):
            self.i.enroll_wireguard(self.request(1))

    def test_thirteenth_active_device_is_rejected_without_peer_mutation(self):
        for number in range(1, 13):
            self.i.enroll_wireguard(self.request(number))
        calls = self.command.call_count
        with self.assertRaisesRegex(PermissionError, 'device_limit'):
            self.i.enroll_wireguard(self.request(13))
        self.assertEqual(self.command.call_count, calls)
        self.assertEqual(len(self.peers), 12)
        # Disabling in the database alone does not free a still-live peer's slot.
        data = self.i.accounts()
        record = data[self.account]['devices'][f'{1:032x}']
        record.update(disabled=True, revoke_pending=True)
        self.i.write_json(self.i.ROOT/'accounts.json', data)
        with self.assertRaisesRegex(PermissionError, 'device_limit'):
            self.i.enroll_wireguard(self.request(13))

    def test_name_reservations_count_once_and_can_finish_at_capacity(self):
        for number in range(1, 13):
            self.i.device_info({'token': self.token, 'device': f'{number:032x}'})
        with self.assertRaisesRegex(PermissionError, 'device_limit'):
            self.i.enroll_wireguard(self.request(13))
        first = self.i.enroll_wireguard(self.request(1))
        self.assertEqual(first['device_number'], 1)
        self.i.revoke_device(self.account, first['device'])
        replacement = self.i.enroll_wireguard(self.request(13))
        self.assertEqual(replacement['device_number'], 13)
        self.assertEqual(self.i.active_device_count(self.i.accounts()[self.account]), 12)

    def test_wrong_tokens_keys_or_types_never_modify_existing_peers(self):
        self.i.enroll_wireguard(self.request())
        before = (self.i.ROOT/'accounts.json').read_bytes(); calls = self.command.call_count
        for values in ({'token': 'invalid'}, {'public_key': key(2)}, {'token': self.other}, {'private_key': 'SECRET'}):
            with self.assertRaises((PermissionError, ValueError)):
                self.i.enroll_wireguard(self.request(**values))
        self.assertEqual(self.command.call_count, calls)
        self.assertEqual(before, (self.i.ROOT/'accounts.json').read_bytes())
        with self.assertRaises(PermissionError):
            self.i.enroll({'token': self.token, 'device': f'{1:032x}', 'csr': '-----BEGIN CERTIFICATE REQUEST-----'+'a'*150})

    def test_bad_and_duplicate_public_keys_are_rejected(self):
        for bad in ('', 'x'*44, base64.b64encode(bytes(32)).decode(), key(1)+'\n'):
            with self.assertRaises(ValueError): self.i.enroll_wireguard(self.request(public_key=bad))
        self.i.enroll_wireguard(self.request())
        for body in (self.request(2, public_key=key(1)), self.request(2, token=self.other, public_key=key(1))):
            with self.assertRaises(PermissionError): self.i.enroll_wireguard(body)
        self.assertEqual(len(self.peers), 1)

    def test_apply_failure_retry_reuses_address_and_device_number(self):
        with patch.object(self.i.wireguard, 'apply_peer', side_effect=RuntimeError('unavailable')):
            with self.assertRaises(RuntimeError): self.i.enroll_wireguard(self.request())
        pending = self.i.accounts()[self.account]['devices'][f'{1:032x}']
        self.assertTrue(pending['enroll_pending'])
        profile = self.i.enroll_wireguard(self.request())
        self.assertEqual(profile['address'], pending['address'])
        self.assertEqual(profile['device_number'], 1)
        self.assertNotIn('enroll_pending', self.i.accounts()[self.account]['devices'][f'{1:032x}'])

    def test_device_revocation_is_durable_isolated_retryable(self):
        first = self.i.enroll_wireguard(self.request()); self.i.enroll_wireguard(self.request(2))
        with patch.object(self.i.wireguard, 'remove_peer', side_effect=RuntimeError('unavailable')):
            with self.assertRaises(RuntimeError): self.i.revoke_device(self.account, first['device'])
        record = self.i.accounts()[self.account]['devices'][first['device']]
        self.assertTrue(record['disabled']); self.assertTrue(record['revoke_pending'])
        with self.assertRaises(PermissionError): self.i.enroll_wireguard(self.request())
        self.assertTrue(self.i.revoke_device(self.account, first['device'])['revoked'])
        self.assertNotIn(key(1), self.peers); self.assertIn(key(2), self.peers)
        calls = self.command.call_count
        self.assertTrue(self.i.revoke_device(self.account, first['device'])['revoked'])
        self.assertEqual(self.command.call_count, calls)
        third = self.i.enroll_wireguard(self.request(3))
        self.assertNotEqual(first['address'], third['address'])
        other_id = self.i.authenticate(self.i.accounts(), self.other)[0]
        with self.assertRaisesRegex(ValueError, 'device_missing'): self.i.revoke_device(other_id, first['device'])

    def test_mixed_account_delete_and_retry_preserve_other_account(self):
        self.i.enroll_wireguard(self.request()); self.i.enroll_wireguard(self.request(2, token=self.other))
        data = self.i.accounts(); data[self.account]['devices']['a'*32] = {'identity': 'device-'+'a'*24, 'enrolled': 1}
        self.i.write_json(self.i.ROOT/'accounts.json', data)
        with patch.object(self.i, 'revoke_certificates', side_effect=RuntimeError('CA_failure')):
            with self.assertRaises(RuntimeError): self.i.delete_account(self.account)
        self.assertNotIn(key(1), self.peers); self.assertIn(key(2), self.peers)
        with self.assertRaises(PermissionError): self.i.authenticate(self.i.accounts(), self.token)
        self.assertTrue(self.i.accounts()[self.account]['delete_pending'])
        with patch.object(self.i, 'revoke_certificates') as certificates:
            self.i.delete_account(self.account)
            certificates.assert_called_once_with({'device-'+'a'*24})
        self.assertTrue(self.i.accounts()[self.account]['deleted'])
        self.i.authenticate(self.i.accounts(), self.other)

    def test_restart_sync_removes_unknown_and_revoked_without_reenabling(self):
        self.i.enroll_wireguard(self.request()); self.i.enroll_wireguard(self.request(2))
        data = self.i.accounts(); data[self.account]['devices'][f'{1:032x}']['disabled'] = True
        self.i.write_json(self.i.ROOT/'accounts.json', data)
        self.peers[key(88)] = '10.78.0.80/32'
        self.i.wireguard.sync(self.i.accounts())
        self.assertEqual(self.peers, {key(2): '10.78.0.3/32'})

    def test_restricted_socket_rejects_all_other_operations_even_for_root(self):
        for op in ('admin-delete-account', 'admin-revoke-device', 'device', 'enroll'):
            handler = object.__new__(self.i.Handler)
            handler.server = SimpleNamespace(wireguard_only=True)
            handler.connection = MagicMock()
            handler.rfile = io.BytesIO(json.dumps({'operation': op, 'id': self.account}).encode()+b'\n')
            handler.wfile = io.BytesIO()
            with patch.object(self.i, 'delete_account') as delete, patch.object(self.i, 'revoke_device') as revoke, patch.object(self.i.time, 'sleep'):
                handler.handle(); delete.assert_not_called(); revoke.assert_not_called()
            self.assertFalse(json.loads(handler.wfile.getvalue())['ok'])
            handler.connection.getsockopt.assert_not_called()

    def test_connection_snapshot_never_uses_secret_dump_and_stale_handshake_offline(self):
        now = 1000
        with patch.object(self.i.wireguard.time, 'time', return_value=now), patch.object(self.i.wireguard, 'command', side_effect=[key(1)+'\t999\n'+key(2)+'\t1\n', key(1)+'\t20\t30\n'+key(2)+'\t0\t0\n']) as cmd:
            result = self.i.wireguard.connections()
        self.assertEqual([r['state'] for r in result['items']], ['ESTABLISHED', 'IDLE'])
        self.assertEqual(result['items'][0]['children'][0], {'bytes_in': 20, 'bytes_out': 30})
        self.assertNotIn('dump', str(cmd.call_args_list))


if __name__ == '__main__': unittest.main()
