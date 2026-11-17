"""Adversarial inputs and publication failures use only synthetic local fixtures."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('taskpack_under_test', ROOT / 'uuid_swap.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
OLD, NEW, OTHER = 'a' * 32, 'b' * 32, 'c' * 32


class SafetyChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.package = self.base / (OLD + '-DEMO')
        self.package.mkdir()
        (self.package / 'task.toml').write_text(f'[task]\nname = "demo/{OLD}"\n')
        self.output = self.base / 'result.zip'

    def cli(self, *args):
        return subprocess.run([sys.executable, '-I', str(ROOT / 'uuid_swap.py'), *map(str, args)],
                              capture_output=True, text=True)

    def repair(self, *args):
        return self.cli('apply', self.package, '--from', OLD, '--to', NEW,
                        '--zip', self.output, *args)

    def archive(self, entries):
        path = self.base / 'input.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            for name, data in entries:
                archive.writestr(name, data)
        return path

    def test_existing_output_requires_explicit_overwrite(self):
        self.output.write_bytes(b'keep me')
        result = self.repair()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_bytes(), b'keep me')
        self.assertEqual(self.repair('--overwrite').returncode, 0)
        self.assertTrue(zipfile.is_zipfile(self.output))

    def test_output_cannot_replace_input_archive_even_with_overwrite(self):
        source = self.archive([(OLD + '-DEMO/task.toml', f'name="{OLD}"')])
        before = source.read_bytes()
        result = self.cli('apply', source, '--from', OLD, '--to', NEW,
                          '--zip', source, '--overwrite')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(source.read_bytes(), before)

    def test_output_cannot_be_inside_input_directory(self):
        self.output = self.package / 'result.zip'
        self.assertNotEqual(self.repair().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_missing_output_is_rejected(self):
        result = self.cli('apply', self.package, '--from', OLD, '--to', NEW)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('requires --zip', result.stderr)

    def test_file_rename_collision_rejected_by_plan_and_apply(self):
        (self.package / (OLD + '.txt')).write_text('original')
        (self.package / (NEW + '.txt')).write_text('existing')
        for mode in ('plan', 'apply'):
            args = ['--zip', self.output] if mode == 'apply' else []
            result = self.cli(mode, self.package, '--from', OLD, '--to', NEW, *args)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn('collision', result.stderr)
        self.assertFalse(self.output.exists())
        self.assertEqual((self.package / (NEW + '.txt')).read_text(), 'existing')

    def test_directory_merge_collision_is_rejected(self):
        for identifier in (OLD, NEW):
            (self.package / identifier).mkdir()
            (self.package / identifier / 'data').write_text(identifier)
        self.assertNotEqual(self.repair().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_required_check_blocks_remaining_identifiers(self):
        (self.package / 'other.txt').write_text(OTHER)
        result = self.repair('--require-check', '--json')
        payload = json.loads(result.stdout)
        self.assertFalse(payload['success'])
        self.assertIn('post-repair check failed', payload['error'])
        self.assertFalse(self.output.exists())

    def test_successful_json_repair_has_integrity_and_digest(self):
        result = self.repair('--require-check', '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload['result']['integrity_verified'])
        self.assertTrue(payload['result']['required_check_passed'])
        self.assertEqual(payload['result']['sha256'], tool.sha256_file(self.output))

    def test_json_scan_and_check(self):
        scan = json.loads(self.cli('scan', self.package, '--json').stdout)
        self.assertEqual(scan['result']['identifiers'][0]['uuid'], OLD)
        check = self.cli('check', self.package, '--client', OLD, '--json')
        self.assertTrue(json.loads(check.stdout)['success'])
        bad = self.cli('check', self.package, '--client', NEW, '--json')
        self.assertFalse(json.loads(bad.stdout)['success'])
        self.assertEqual(bad.returncode, 1)

    def test_json_invalid_input_is_one_parseable_result(self):
        result = self.cli('scan', self.base / 'missing', '--json')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)['success'])
        self.assertEqual(result.stderr, '')

    def test_symlinks_rejected_without_reading_target(self):
        outside = self.base / 'private.txt'
        outside.write_text('outside')
        (self.package / 'link').symlink_to(outside)
        for mode in ('scan', 'plan', 'apply', 'check'):
            result = self.cli(mode, self.package, '--from', OLD, '--to', NEW,
                              *(['--zip', self.output] if mode == 'apply' else []))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('symlink', result.stderr)
        self.assertEqual(outside.read_text(), 'outside')

    def test_unsafe_archive_paths_are_rejected(self):
        for name in ('../escape.txt', '/absolute.txt', 'root/../escape',
                     'root\\escape', 'C:/escape', 'root//file', 'root/./file'):
            with self.subTest(name=name):
                source = self.archive([(name, 'bad')])
                result = self.cli('scan', source)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('unsafe ZIP path', result.stderr)
        self.assertFalse((self.base / 'escape.txt').exists())

    def test_zip_multiple_roots_and_top_level_files_rejected(self):
        for entries in ([('one/a', 'a'), ('two/b', 'b')], [('loose.txt', 'a')]):
            result = self.cli('scan', self.archive(entries))
            self.assertNotEqual(result.returncode, 0)

    def test_zip_duplicates_and_case_collisions_rejected(self):
        for names in [('root/a', 'root/a'), ('root/a', 'root/A'),
                      ('root/A/x', 'root/a/y')]:
            with self.subTest(names=names):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    source = self.archive([(name, 'x') for name in names])
                self.assertNotEqual(self.cli('scan', source).returncode, 0)

    def test_zip_symlink_rejected(self):
        entry = zipfile.ZipInfo('root/link')
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        source = self.archive([(entry, '../../outside')])
        result = self.cli('scan', source)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('symlink', result.stderr)

    def test_corrupt_zip_reports_error(self):
        source = self.archive([('root/payload', b'unique-payload')])
        data = source.read_bytes().replace(b'unique-payload', b'broken-payload')
        source.write_bytes(data)
        result = self.cli('scan', source, '--json')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CRC', json.loads(result.stdout)['error'])

    def test_zip_limits_enforced_before_extraction(self):
        source = self.archive([('root/a', b'12345')])
        for limit in ('MAX_ENTRIES', 'MAX_FILE_BYTES', 'MAX_TOTAL_BYTES'):
            work = self.base / limit
            work.mkdir()
            with mock.patch.object(tool, limit, 0):
                with self.assertRaises(ValueError):
                    tool.materialise(str(source), str(work))
            self.assertFalse((work / '_x').exists())

    def test_high_compression_ratio_rejected(self):
        source = self.base / 'compressed.zip'
        with zipfile.ZipFile(source, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('root/payload', b'0' * 2000000)
        self.assertNotEqual(self.cli('scan', source).returncode, 0)

    def test_empty_directories_and_modes_survive_archive_round_trip(self):
        empty = self.package / 'empty'
        empty.mkdir()
        empty.chmod(0o750)
        script = self.package / 'run.sh'
        script.write_text('#!/bin/sh\nexit 0\n')
        script.chmod(0o755)
        self.assertEqual(self.repair().returncode, 0)
        work = self.base / 'work'
        work.mkdir()
        restored = Path(tool.materialise(str(self.output), str(work)))
        self.assertTrue((restored / 'empty').is_dir())
        self.assertEqual(stat.S_IMODE((restored / 'empty').stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((restored / 'run.sh').stat().st_mode), 0o755)

    def test_atomic_write_failure_keeps_existing_output_and_removes_temp(self):
        self.output.write_bytes(b'existing')
        with mock.patch.object(zipfile.ZipFile, 'writestr', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                tool.write_zip(str(self.package), str(self.output), overwrite=True)
        self.assertEqual(self.output.read_bytes(), b'existing')
        self.assertEqual(list(self.base.glob('.taskpack-*')), [])

    def test_publication_permission_error_keeps_output(self):
        self.output.write_bytes(b'existing')
        with mock.patch.object(tool.os, 'replace', side_effect=PermissionError('denied')):
            with self.assertRaises(PermissionError):
                tool.write_zip(str(self.package), str(self.output), overwrite=True)
        self.assertEqual(self.output.read_bytes(), b'existing')
        self.assertEqual(list(self.base.glob('.taskpack-*')), [])

    def test_interrupted_archive_write_does_not_publish(self):
        with mock.patch.object(zipfile.ZipFile, 'writestr', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                tool.write_zip(str(self.package), str(self.output))
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.base.glob('.taskpack-*')), [])

    def test_exclusive_publication_preserves_concurrent_writers_output(self):
        def competing_writer(src, dst):
            Path(dst).write_bytes(b'other writer')
            raise FileExistsError('destination appeared')
        with mock.patch.object(tool.os, 'link', side_effect=competing_writer):
            with self.assertRaises(FileExistsError):
                tool.write_zip(str(self.package), str(self.output))
        self.assertEqual(self.output.read_bytes(), b'other writer')
        self.assertEqual(list(self.base.glob('.taskpack-*')), [])

    def test_required_check_failure_preserves_existing_output(self):
        (self.package / 'task.toml').unlink()
        self.output.write_bytes(b'original output')
        result = self.repair('--require-check', '--overwrite')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_bytes(), b'original output')

    def test_json_plan_reports_changes_without_mutating_input(self):
        before = tool.repair_inventory(str(self.package))
        result = self.cli('plan', self.package, '--from', OLD, '--to', NEW, '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        plans = json.loads(result.stdout)['result']['plans']
        self.assertEqual(plans[0]['edits'][0]['path'], 'task.toml')
        self.assertEqual(before, tool.repair_inventory(str(self.package)))

    def test_unexpected_change_to_renamed_file_is_detected(self):
        nested = self.package / OLD
        nested.mkdir()
        (nested / 'payload').write_bytes(b'untouched')
        real_rename = tool.os.rename
        def corrupting_rename(src, dst):
            real_rename(src, dst)
            payload = Path(dst) / 'payload'
            if payload.is_file():
                payload.write_bytes(b'corrupt')
        with mock.patch.object(tool.os, 'rename', side_effect=corrupting_rename):
            with self.assertRaisesRegex(ValueError, 'integrity verification failed'):
                tool.apply(str(self.package), [OLD], NEW, True)


if __name__ == '__main__':
    unittest.main()
