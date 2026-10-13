"""Exercise GUI routing methods without starting Tk or importing device services."""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


class FallbackTests(unittest.TestCase):
    def setUp(self):
        tree = ast.parse((Path(__file__).resolve().parents[1] / 'ufade.py').read_text())
        names = {'get_developer_device', 'run_userspace_developer', 'userspace_tunnel_failed',
                 'ensure_legacy_tunnel', 'log_userspace_retry'}
        methods = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in names]
        self.log = Mock()
        self.device = object()
        self.discovery = Mock(return_value=[self.device])
        self.env = {'log': self.log, 'get_tunneld_devices': self.discovery, 'udid': 'test'}
        exec(compile(ast.Module(body=methods, type_ignores=[]), '<GUI methods>', 'exec'), self.env)
        cls = type('App', (), {name: self.env[name] for name in names})
        class ImmediateThread:
            def __init__(self, target, **kwargs): self.target = target
            def start(self): self.target()
        self.env['threading'] = SimpleNamespace(Thread=ImmediateThread)
        self.env['ctk'] = SimpleNamespace(IntVar=Mock())
        self.app = cls()
        self.app.text = Mock()
        self.app.wait_variable = Mock()
        self.app.use_userspace_tunnel = True
        self.app.userspace_tunnel = Mock(active=True, serial='test')
        self.app.ensure_legacy_tunnel = Mock(return_value=True)

    def test_start_failure_logs_and_signals_completion_without_error_dialog(self):
        self.app.userspace_tunnel.ensure_connected.side_effect = RuntimeError('TLS failed')
        change = Mock()
        self.app.run_userspace_developer(change)
        self.assertFalse(self.app.use_userspace_tunnel)
        self.app.userspace_tunnel.close.assert_called_once()
        self.assertIn('TLS failed', self.log.call_args.args[0])
        change.set.assert_called_once_with(1)

    def test_refresh_failure_selects_legacy_device(self):
        self.app.userspace_tunnel.ensure_connected.side_effect = ConnectionError('disconnected')
        self.assertIs(self.app.get_developer_device(), self.device)
        self.app.ensure_legacy_tunnel.assert_called_once()
        self.assertFalse(self.app.use_userspace_tunnel)
        self.assertIn('disconnected', self.log.call_args.args[0])

    def test_declining_fallback_does_not_fetch_device(self):
        self.app.userspace_tunnel.ensure_connected.side_effect = ConnectionError('disconnected')
        self.app.ensure_legacy_tunnel.return_value = False
        self.assertIsNone(self.app.get_developer_device())
        self.discovery.assert_not_called()

    def test_success_uses_userspace_without_prompt(self):
        self.app.userspace_tunnel.ensure_connected.return_value = self.device
        self.assertIs(self.app.get_developer_device(), self.device)
        self.app.ensure_legacy_tunnel.assert_not_called()
        self.discovery.assert_not_called()

    def test_legacy_selection_does_not_retry_userspace(self):
        self.app.use_userspace_tunnel = False
        self.assertIs(self.app.get_developer_device(), self.device)
        self.app.userspace_tunnel.ensure_connected.assert_not_called()

    def test_legacy_prompt_requires_yes_before_starting(self):
        class Var:
            def __init__(self, owner=None, value=0): self.value = value
            def get(self): return self.value
            def set(self, value): self.value = value
        class Thread:
            def __init__(self, target): self.target = target
            def start(self): self.target()
        self.env['threading'] = SimpleNamespace(Thread=Thread)
        self.env['ctk'] = SimpleNamespace(BooleanVar=Var, CTkButton=Mock())
        for answer in (False, True):
            with self.subTest(answer=answer):
                self.app.change = Var()
                self.app.tun = None
                self.app.text = Mock()
                self.app.dynamic_frame = object()
                self.app.stfont = None
                self.app.check_tun = Mock(side_effect=lambda var: var.set(1))
                self.app.run_ios17_developer = Mock(side_effect=lambda var: var.set(1))
                self.app.show_main_menu = Mock()
                def wait(var):
                    if var is not self.app.change:
                        var.set(answer)
                self.app.wait_variable = wait
                result = self.env['ensure_legacy_tunnel'](self.app)
                self.assertEqual(result, answer)
                self.assertIn('This requires administrative privileges. Do you want to continue?',
                              self.app.text.configure.call_args.kwargs['text'])
                self.assertEqual(self.app.run_ios17_developer.call_count, int(answer))
