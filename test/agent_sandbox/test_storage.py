import errno
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('probe_storage', ROOT / 'tools/agent_sandbox/probe_storage.py')
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'sentinel').write_bytes(b'unchanged')

    def test_real_observations_and_cleanup(self):
        result = storage.probe_directory(self.root)
        self.assertEqual(result['cleanup']['status'], 'removed')
        self.assertIn(result['case_lookup']['status'], ('sensitive', 'insensitive'))
        self.assertIn(result['hardlinks']['status'], ('supported', 'denied', 'unsupported'))
        self.assertEqual((self.root / 'sentinel').read_bytes(), b'unchanged')
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['sentinel'])

    def test_hardlink_denial_does_not_become_copy_or_support(self):
        with patch.object(storage.os, 'link', side_effect=PermissionError(errno.EPERM, 'denied')):
            result = storage.probe_directory(self.root)
        self.assertEqual(result['hardlinks']['status'], 'denied')
        self.assertEqual(result['hardlinks']['errno'], errno.EPERM)
        self.assertEqual(result['cleanup']['status'], 'removed')

    def test_cannot_create_probe_is_unknown_not_insensitive(self):
        with patch.object(storage.tempfile, 'mkdtemp', side_effect=PermissionError(errno.EACCES, 'denied')):
            result = storage.probe_directory(self.root)
        self.assertEqual(result['case_lookup']['status'], 'unknown')
        self.assertEqual(result['hardlinks']['status'], 'unknown')
        self.assertEqual(result['cleanup']['status'], 'not-created')
        self.assertEqual(result['error']['errno'], errno.EACCES)

    def test_missing_target_is_not_created(self):
        target = self.root / 'absent'
        result = storage.probe_directory(target)
        self.assertEqual(result['error']['errno'], errno.ENOENT)
        self.assertFalse(target.exists())

    def test_non_directory_target(self):
        result = storage.probe_directory(self.root / 'sentinel')
        self.assertEqual(result['error']['errno'], errno.ENOTDIR)
        self.assertEqual((self.root / 'sentinel').read_bytes(), b'unchanged')

    def test_cleanup_failure_names_residue_and_is_not_reported_removed(self):
        with patch.object(storage.shutil, 'rmtree', side_effect=PermissionError(errno.EACCES, 'cleanup denied')):
            result = storage.probe_directory(self.root)
        self.assertEqual(result['cleanup']['status'], 'failed')
        residue = Path(result['cleanup']['remaining_path'])
        self.assertEqual(residue.parent, self.root)
        self.assertTrue(residue.is_dir())
        storage.shutil.rmtree(residue)

    def test_copy_is_not_a_hardlink(self):
        def copy_instead(source, target):
            Path(target).write_bytes(Path(source).read_bytes())
        with patch.object(storage.os, 'link', side_effect=copy_instead):
            result = storage.probe_directory(self.root)
        self.assertEqual(result['hardlinks']['status'], 'inconsistent')
        self.assertFalse(result['hardlinks']['shared_identity_and_content'])
        self.assertEqual(result['cleanup']['status'], 'removed')

    def test_case_probe_error_does_not_hide_hardlink_observation(self):
        with patch.object(storage, 'case_lookup', side_effect=PermissionError(errno.EACCES, 'denied')):
            result = storage.probe_directory(self.root)
        self.assertEqual(result['case_lookup']['status'], 'unknown')
        self.assertIn(result['hardlinks']['status'], ('supported', 'denied', 'unsupported'))
        self.assertEqual(result['cleanup']['status'], 'removed')

    def test_cli_reports_all_targets_and_nonzero_for_unknown(self):
        import contextlib
        import io
        import json
        output = io.StringIO()
        with patch('sys.argv', ['probe_storage.py', str(self.root / 'absent'), str(self.root)]), contextlib.redirect_stdout(output):
            code = storage.main()
        report = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(report['enforcement'], 'not-connected')
        self.assertEqual(len(report['results']), 2)
        self.assertEqual(report['results'][1]['cleanup']['status'], 'removed')

    def test_cli_denied_hardlinks_is_successful_observation(self):
        import contextlib
        import io
        with patch('sys.argv', ['probe_storage.py', str(self.root)]), \
                patch.object(storage.os, 'link', side_effect=PermissionError(errno.EPERM, 'denied')), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(storage.main(), 0)
