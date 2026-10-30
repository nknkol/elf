import importlib.util
from pathlib import Path
import tempfile
import unittest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('launch', ROOT/'tools/agent_sandbox/launch.py')
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)


class LaunchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ('brew/bin', 'workspace'):
            (self.root/name).mkdir(parents=True)
        self.state = self.root/'state'
        self.compiled = dict(state=str(self.state), mounts=[
            dict(source=str(self.root/'brew'), target='/opt/brew', access='ro', kind='bind'),
            dict(source=str(self.root/'workspace'), target='/workspace', access='rw', kind='bind'),
            dict(source='/dev/null', target='/dev/null', access='rw', kind='bind'),
            dict(source=str(self.state/'home'), target='/home/agent', access='rw', kind='private'),
            dict(source=str(self.state/'tmp'), target='/tmp', access='rw', kind='private')])

    def test_vector_follows_volume_order(self):
        argv = launch.command_line(self.compiled, self.state/'root', Path('/l'), '/workspace',
                                   ['/bin/sh', '-c', 'true'], ['A=1'])
        self.assertEqual(argv[argv.index('--guard-file-access') + 1], 'drwwww')
        volumes = [argv[i + 1] for i, a in enumerate(argv) if a == '-v']
        self.assertEqual(volumes[0], f'{self.root}/brew:/opt/brew')
        self.assertEqual(argv[argv.index('--'):], ['--', './.elf-exec', '/workspace',
                                                   '/bin/sh', '/bin/sh', '-c', 'true'])
        self.assertIn('--revalidate-file-fds', argv)
        self.assertIn('--allow-local-output', argv)

    def test_limits(self):
        many = dict(self.compiled, mounts=self.compiled['mounts'] * 4)
        with self.assertRaises(launch.ProfileError):
            launch.command_line(many, self.state/'root', Path('/l'), '/', ['/bin/sh'], [])
        with self.assertRaises(launch.ProfileError):
            launch.command_line(self.compiled, self.state/'root', Path('/l'), '/', ['sh'], [])
        with self.assertRaises(launch.ProfileError):
            launch.environment(self.compiled, [f'K{i}=v' for i in range(16)], None)
        with self.assertRaises(launch.ProfileError):
            launch.environment(self.compiled, ['LONG=' + 'x' * 300], None)

    def test_clean_environment(self):
        env = dict(e.split('=', 1) for e in launch.environment(self.compiled, ['EXTRA=1'], 'xterm'))
        self.assertEqual(env['HOME'], '/home/agent')
        self.assertEqual(env['TMPDIR'], '/tmp')
        self.assertTrue(env['PATH'].startswith('/opt/brew/bin:'))
        self.assertEqual((env['TERM'], env['EXTRA']), ('xterm', '1'))
        self.assertNotIn('XDG_CACHE_HOME', env)

    def test_skeleton_contains_only_mountpoints(self):
        root = launch.prepare_state(self.compiled)
        self.assertEqual(sorted(p.name for p in root.iterdir()),
                         ['.elf-skeleton', 'dev', 'home', 'opt', 'tmp', 'workspace'])
        self.assertTrue((root/'dev/null').is_file())
        self.assertTrue((root/'opt/brew').is_dir())
        self.assertEqual((self.state/'home').stat().st_mode & 0o777, 0o700)
        (root/'stale').write_text('x')
        root = launch.prepare_state(self.compiled)
        self.assertFalse((root/'stale').exists())

    def test_foreign_root_is_not_removed(self):
        (self.state/'root').mkdir(parents=True)
        (self.state/'root/data').write_text('keep')
        with self.assertRaises(launch.ProfileError):
            launch.prepare_state(self.compiled)
        self.assertEqual((self.state/'root/data').read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
