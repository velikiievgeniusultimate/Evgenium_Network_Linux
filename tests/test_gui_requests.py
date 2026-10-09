import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import MagicMock, patch

spec=importlib.util.spec_from_file_location('gui',Path(__file__).parents[1]/'src/evgenium_gui.py')
gui=importlib.util.module_from_spec(spec);spec.loader.exec_module(gui)

class GuiRequestTests(unittest.TestCase):
    def test_disconnected_poll_does_not_try_to_reply_twice(self):
        handler=gui.Handler.__new__(gui.Handler)
        handler.send_response=MagicMock();handler.send_header=MagicMock()
        handler.end_headers=MagicMock(side_effect=BrokenPipeError())
        handler.wfile=MagicMock()
        handler._json({'ok':True})
        handler.send_response.assert_called_once()
        handler.wfile.write.assert_not_called()

    def test_poll_timeout_is_shorter_than_action_and_stdin_is_closed(self):
        with patch.object(gui.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'{}','')) as run:
            gui.run_vpn_json(['ui','state'])
            self.assertEqual(run.call_args.kwargs['timeout'],10)
            self.assertEqual(run.call_args.kwargs['stdin'],subprocess.DEVNULL)
            gui.run_vpn(['toggle'])
            self.assertGreaterEqual(run.call_args.kwargs['timeout'],700)
