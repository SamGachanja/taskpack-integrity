#!/usr/bin/env python3
"""Self-check for uuid_swap.py. Run: python3 -I test_uuid_swap.py"""
import os, shutil, subprocess, sys, tempfile, zipfile, hashlib

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uuid_swap.py')
OLD = 'a' * 32
NEW = 'b' * 32
SLUG = '-TASKPACK-INTEGRITY-TEST-TASK'


def build_fixture(d):
    root = os.path.join(d, OLD + SLUG)
    os.makedirs(os.path.join(root, 'tests'))
    os.makedirs(os.path.join(root, 'execution_logs', 'single-opencode-agent', NEW + '__trial1'))
    open(os.path.join(root, 'task.toml'), 'w').write(
        f'[task]\nname = "taskpack-integrity/{OLD}{SLUG}"\n')
    open(os.path.join(root, 'tests', 'verify.py'), 'w').write('# no id here\n')
    open(os.path.join(root, 'tests', 'test.sh'), 'w').write('#!/bin/sh\nexit 0\n')
    os.chmod(os.path.join(root, 'tests', 'test.sh'), 0o755)
    # the logs carry the NEW id
    open(os.path.join(root, 'execution_logs', 'single-opencode-agent',
                      NEW + '__trial1', 'result.json'), 'w').write(
        f'{{"task": "{NEW}"}}\n')
    # a log file that carries the OLD id
    open(os.path.join(root, 'execution_logs', 'job.log'), 'w').write(f'ran {OLD}\n')
    return root


def tool(*args, stdin=None):
    return subprocess.run([sys.executable, '-I', TOOL, *args], capture_output=True, text=True,
                          input=stdin, stdin=None if stdin is not None else subprocess.DEVNULL)


def run(*args):
    r = tool(*args)
    assert r.returncode == 0, r.stderr or r.stdout
    return r.stdout


def sha(p):
    return hashlib.sha256(open(p, 'rb').read()).hexdigest()


def extract(z, d):
    with zipfile.ZipFile(z) as zz:
        zz.extractall(d)
    return os.path.join(d, os.listdir(d)[0])


def all_text(root):
    out = []
    for dp, dn, fn in os.walk(root):
        out += dn + fn
        out += [open(os.path.join(dp, n), errors='ignore').read() for n in fn]
    return '\n'.join(out + [os.path.basename(root)])


def mode_in_zip(z, suffix):
    with zipfile.ZipFile(z) as zz:
        info = next(i for i in zz.infolist() if i.filename.endswith(suffix))
    return (info.external_attr >> 16) & 0o777


def main():
    d = tempfile.mkdtemp(prefix='uuidswap_test_')
    try:
        root = build_fixture(d)

        out = run('plan', root, '--from', OLD, '--to', NEW)
        assert '1 path rename' in out, out
        assert 'task.toml' in out, out
        assert 'INCLUDED' in out, "logs are rewritten by default"

        z1 = os.path.join(d, 'o1.zip')
        out = run('apply', root, '--from', OLD, '--to', NEW, '--zip', z1)
        assert 'content changed unexpectedly: 0' in out, out

        top = extract(z1, os.path.join(d, 'x'))
        assert os.path.basename(top) == NEW + SLUG, top
        toml = open(os.path.join(top, 'task.toml')).read()
        assert NEW in toml and OLD not in toml, toml
        joblog = open(os.path.join(top, 'execution_logs', 'job.log')).read()
        assert OLD not in joblog, "logs should be rewritten by default (one uuid throughout)"

        # permissions survive: test.sh stays executable, from a dir and from a zip input
        assert mode_in_zip(z1, 'tests/test.sh') == 0o755, oct(mode_in_zip(z1, 'tests/test.sh'))
        assert mode_in_zip(z1, 'tests/verify.py') == 0o644
        z1b = os.path.join(d, 'o1b.zip')
        run('apply', z1, '--from', NEW, '--to', OLD, '--zip', z1b)
        assert mode_in_zip(z1b, 'tests/test.sh') == 0o755, 'mode lost when the input is a zip'

        # reproducibility: same input, same command, identical bytes
        root2 = build_fixture(os.path.join(d, 'second'))
        z2 = os.path.join(d, 'o2.zip')
        run('apply', root2, '--from', OLD, '--to', NEW, '--zip', z2)
        assert sha(z1) == sha(z2), 'zip output is not byte-reproducible'

        # --keep-logs leaves them alone
        root3 = build_fixture(os.path.join(d, 'third'))
        z3 = os.path.join(d, 'o3.zip')
        out = run('apply', root3, '--from', OLD, '--to', NEW, '--keep-logs', '--zip', z3)
        assert '--include-logs' not in out and 'without --keep-logs' in out, out
        t3 = extract(z3, os.path.join(d, 'x3'))
        assert OLD in open(os.path.join(t3, 'execution_logs', 'job.log')).read()

        # check: FAIL on the mixed fixture, PASS once consistent
        root4 = build_fixture(os.path.join(d, 'fourth'))
        bad = tool('check', root4)
        assert bad.returncode == 1 and 'must carry exactly one' in bad.stdout, bad.stdout
        good = tool('check', top)
        assert good.returncode == 0 and 'PASS' in good.stdout, good.stdout

        # check --client: a package consistent on the TRAINER's uuid must fail, and the
        # fix it prints is the current command (no --include-logs)
        trainer_only = tool('check', top, '--client', OLD)
        o = trainer_only.stdout
        assert trainer_only.returncode == 1, o
        assert 'package folder carries' in o and 'task.toml' in o, o
        assert 'trial dir(s)' in o and 'execution_logs/' in o, o
        assert f'apply <pkg> --from {NEW} --to {OLD} --zip out.zip' in o, o
        assert '--include-logs' not in o, o
        mixed = tool('check', root4, '--client', OLD)
        assert mixed.returncode == 1 and '--include-logs' not in mixed.stdout, mixed.stdout
        assert f'--from {NEW} --to {OLD}' in mixed.stdout, mixed.stdout
        # dashed / upper-case client uuid is accepted
        dashed = OLD.upper()
        dashed = '-'.join([dashed[:8], dashed[8:12], dashed[12:16], dashed[16:20], dashed[20:]])
        assert tool('check', top, '--client', dashed).returncode == 1

        # trainer's uuid back to the client's: no --force, logs rewritten too
        root5 = build_fixture(os.path.join(d, 'fifth'))   # client OLD, logs ran as trainer NEW
        z5 = os.path.join(d, 'o5.zip')
        r5 = tool('apply', root5, '--from', NEW, '--to', OLD, '--zip', z5)
        assert r5.returncode == 0, r5.stdout + r5.stderr
        assert 'REFUSING' not in r5.stdout, r5.stdout
        t5 = extract(z5, os.path.join(d, 'x5'))
        assert NEW not in all_text(t5), 'trainer uuid left behind'
        assert os.path.isdir(os.path.join(t5, 'execution_logs', 'single-opencode-agent',
                                          OLD + '__trial1'))
        ok = tool('check', z5, '--client', OLD)
        assert ok.returncode == 0 and "it is the client's" in ok.stdout, ok.stdout

        # several wrong ids in one run (repeated and comma-separated --from)
        THIRD = 'c' * 32
        root6 = build_fixture(os.path.join(d, 'sixth'))
        open(os.path.join(root6, 'tests', 'verify.py'), 'a').write(f'# {THIRD}\n')
        z6 = os.path.join(d, 'o6.zip')
        run('apply', root6, '--from', f'{NEW},{THIRD}', '--to', OLD, '--zip', z6)
        assert tool('check', z6, '--client', OLD).returncode == 0

        # interactive: asks for the client's uuid and swaps everything to it
        root7 = build_fixture(os.path.join(d, 'seventh'))
        z7 = os.path.join(d, 'o7.zip')
        answers = '\n'.join([root7, OLD, '', 'n', 'y', z7]) + '\n'
        r7 = subprocess.run([sys.executable, '-I', TOOL], input=answers,
                            capture_output=True, text=True)
        assert r7.returncode == 0 and os.path.isfile(z7), r7.stdout + r7.stderr
        assert "Client's uuid" in r7.stdout, r7.stdout
        t7 = extract(z7, os.path.join(d, 'x7'))
        assert NEW not in all_text(t7) and os.path.basename(t7) == OLD + SLUG
        assert mode_in_zip(z7, 'tests/test.sh') == 0o755

        # guard rails
        bad = tool('apply', root, '--from', OLD, '--to', 'nothex')
        assert bad.returncode != 0, 'should reject a non-hex target id'
        bad = tool('check', root, '--client', 'nothex')
        assert bad.returncode != 0, 'should reject a non-hex client id'

        print('all checks passed')
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    main()
