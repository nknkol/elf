import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('plan', ROOT/'tools/agent_sandbox/plan.py')
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ('brew', 'workspace'):
            (self.root/name).mkdir()
        self.profile = json.loads((ROOT/'profiles/agent.json').read_text())

    def compile(self, profile=None, **changes):
        args = dict(brew_prefix=str(self.root/'brew'), workspace=str(self.root/'workspace'), state=str(self.root/'state'))
        args.update(changes)
        return plan.compile_profile(self.profile if profile is None else profile, **args)

    def test_default_deny_and_component_boundaries(self):
        p = self.compile()
        for path in ('/etc/passwd', '/workspace-other/file', '/home/agent-other/key'):
            self.assertEqual(plan.access_for(p, path), 'deny')
        self.assertEqual(plan.access_for(p, '/workspace/file'), 'rw')
        self.assertEqual(plan.access_for(p, str(self.root/'brew/bin/tool')), 'ro')

    def test_private_backing_is_not_created_by_planning(self):
        p = self.compile()
        self.assertFalse((self.root/'state').exists())
        self.assertEqual(plan.access_for(p, '/home/agent/.cache/tool'), 'rw')
        self.assertEqual(p['enforcement'], 'not-connected')

    def test_symlink_host_source_preserves_guest_spelling(self):
        (self.root/'alias').symlink_to('brew')
        p = self.compile(brew_prefix=str(self.root/'alias'))
        m = next(m for m in p['mounts'] if m['access'] == 'ro')
        self.assertEqual(m['source'], str(self.root/'brew'))
        self.assertEqual(m['target'], str(self.root/'alias'))

    def test_missing_source(self):
        with self.assertRaises(plan.ProfileError): self.compile(brew_prefix=str(self.root/'absent'))

    def test_state_cannot_be_exposed(self):
        for state in (self.root/'workspace/state', self.root):
            with self.assertRaises(plan.ProfileError): self.compile(state=str(state))

    def test_case_sensitive_siblings_remain_separate(self):
        upper = self.root/'Case'
        lower = self.root/'case'
        upper.mkdir()
        if lower.exists():
            self.skipTest('Temporary backing is case insensitive')
        lower.mkdir()
        self.compile(workspace=str(upper), state=str(lower))

    def test_case_alias_state_overlap_on_home(self):
        home = Path('/storage/Users/currentUser')
        if not home.is_dir():
            self.skipTest('HarmonyOS home backing unavailable')
        with tempfile.TemporaryDirectory(prefix='.elf-plan-test-', dir=home) as tmp:
            base = Path(tmp)
            (base/'Case').mkdir()
            alias = base/'case'
            if not alias.exists():
                self.skipTest('Home backing is case sensitive')
            (base/'Case/child').mkdir()
            for source, state in ((base/'Case', alias),
                                  (base/'Case', alias/'future/deep'),
                                  (base/'Case/child', alias)):
                with self.subTest(source=source, state=state):
                    with self.assertRaises(plan.ProfileError):
                        self.compile(workspace=str(source), state=str(state))
            self.assertFalse((alias/'future').exists())

    def test_identity_errors_fail_closed(self):
        for error in (PermissionError('denied'), NotADirectoryError('not a directory')):
            with mock.patch.object(plan.os, 'stat', side_effect=error):
                with self.assertRaises(plan.ProfileError):
                    plan.host_contains('/one', '/other/future')

    def test_unsafe_paths(self):
        for value in ('relative', '/a/../b', '/a//b', '/a/.', '//a', '/a\0b'):
            with self.subTest(value=value), self.assertRaises(plan.ProfileError): plan.absolute(value)

    def test_unknown_fields_and_permissions_rejected(self):
        for key, value in [('extra', True), ('default', 'allow'), ('version', True)]:
            p = copy.deepcopy(self.profile); p[key] = value
            with self.assertRaises(plan.ProfileError): self.compile(p)
        self.profile['mounts'][0]['access'] = 'readonly'
        with self.assertRaises(plan.ProfileError): self.compile()

    def test_duplicate_and_root_targets(self):
        for target in ('/', '/workspace'):
            p = copy.deepcopy(self.profile); p['mounts'][0]['target'] = target
            with self.assertRaises(plan.ProfileError): self.compile(p)

    def test_nested_readonly_override(self):
        self.profile['mounts'].append(dict(source='${BREW_PREFIX}', target='/workspace/tools', access='ro'))
        p = self.compile()
        self.assertEqual(plan.access_for(p, '/workspace/tools/bin'), 'ro')
        self.assertEqual(plan.access_for(p, '/workspace/tools-other'), 'rw')


class UnresolvedSourceTests(unittest.TestCase):
    def test_unstatable_explicit_source_keeps_spelling(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'workspace').mkdir()
            profile = {'version': 1, 'default': 'deny', 'private': [], 'mounts': [
                {'source': '/opaque/socket', 'access': 'ro'}]}
            original = plan.Path.resolve

            def resolve(path, strict=False):
                if str(path).startswith('/opaque'):
                    raise PermissionError(13, 'Permission denied')
                return original(path, strict=strict)
            with mock.patch.object(plan.Path, 'resolve', resolve):
                p = plan.compile_profile(profile, brew_prefix=str(root), workspace=str(root/'workspace'),
                                         state=str(root/'state'))
            self.assertEqual(p['mounts'], [dict(source='/opaque/socket', target='/opaque/socket',
                                                access='ro', kind='bind', unresolved=True)])


if __name__ == '__main__':
    unittest.main()
