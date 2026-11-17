#!/usr/bin/env python3
"""Inspect and rewrite task-package UUIDs with TaskPack Integrity.

Accepts a .zip or an extracted directory. The input is never modified: work is
done on a copy in a temp directory and written out as a new zip.

Output zips are byte-reproducible: entries are sorted and timestamps fixed, so
running the same command twice produces an identical file with the same SHA-256.
File permissions are kept, so test.sh stays executable.

  check  <pkg> [--client C]          verify folder name, task.toml and the execution
                                     logs all declare the SAME uuid, and that it is
                                     the client's uuid C (exit 1 if not)
  scan   <pkg>                       list every 32-hex id, in names and in contents
  plan   <pkg> --from X --to C       show exactly what would change (no writes)
  apply  <pkg> --from X --to C       do it, verify, and optionally re-zip

The rule: a package carries exactly ONE uuid, and it is the CLIENT's uuid. The
folder name, task.toml, the execution logs and every other file must carry it.
A trainer-generated uuid is swapped back to the client's everywhere, including
execution_logs/. --from can be repeated (or comma-separated) to swap several ids
to the client's uuid in one run.

`check` without --client asks for the client's uuid when run in a terminal.

Every run writes a SHA-256 manifest before and after, so the report can state
positively that no other file changed.
"""
import argparse, hashlib, os, re, shutil, stat, sys, tempfile, zipfile
from collections import Counter, defaultdict

HEX32 = re.compile(r'(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])')
LOGDIR = 'execution_logs'


def norm_uuid(s):
    """Accept a uuid with or without dashes, any case. Return 32 lowercase hex or None."""
    t = (s or '').strip().lower().replace('-', '')
    return t if HEX32.fullmatch(t) else None


def parse_ids(values):
    """--from values: repeatable and/or comma-separated. Order kept, duplicates dropped."""
    out = []
    for v in values or []:
        for part in v.split(','):
            part = part.strip()
            if part:
                out.append(norm_uuid(part) or part)
    return list(dict.fromkeys(out))


def walk(root):
    for dp, dn, fn in os.walk(root):
        dn.sort(); fn.sort()
        for n in fn:
            yield os.path.join(dp, n)


def rel(root, p):
    return os.path.relpath(p, root)


def manifest(root):
    out = {}
    for p in walk(root):
        h = hashlib.sha256()
        with open(p, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        out[rel(root, p)] = h.hexdigest()
    return out


def in_logs(relpath):
    return relpath.split(os.sep)[0] == LOGDIR or f'{os.sep}{LOGDIR}{os.sep}' in f'{os.sep}{relpath}'


def scan(root):
    names, content = Counter(), Counter()
    where = defaultdict(set)
    for m in HEX32.findall(os.path.basename(root)):
        names[m] += 1
        where[m].add('path name: <package root> ' + os.path.basename(root))
    for dp, dn, fn in os.walk(root):
        for n in list(dn) + list(fn):
            for m in HEX32.findall(n):
                names[m] += 1
                where[m].add('path name: ' + rel(root, os.path.join(dp, n)))
    for p in walk(root):
        try:
            b = open(p, 'rb').read()
        except OSError:
            continue
        t = b.decode('utf-8', errors='ignore')
        for m in HEX32.findall(t):
            content[m] += 1
            where[m].add('content: ' + rel(root, p))
    return names, content, where


def find_changes(root, old, new, include_logs):
    """Return (renames, edits). Renames are deepest-first."""
    renames, edits = [], []
    # the package root's own name is not yielded by os.walk, but it carries the id
    if old in os.path.basename(root):
        renames.append((root, os.path.join(os.path.dirname(root),
                                           os.path.basename(root).replace(old, new))))
    for dp, dn, fn in os.walk(root):
        for n in list(dn) + list(fn):
            if old in n:
                src = os.path.join(dp, n)
                r = rel(root, src)
                if not include_logs and in_logs(r):
                    continue
                renames.append((src, os.path.join(dp, n.replace(old, new))))
    renames.sort(key=lambda t: t[0].count(os.sep), reverse=True)
    # root rename must happen last: renaming it first invalidates every other path
    renames = [r for r in renames if r[0] != root] + [r for r in renames if r[0] == root]

    ob = old.encode()
    for p in walk(root):
        r = rel(root, p)
        if not include_logs and in_logs(r):
            continue
        try:
            b = open(p, 'rb').read()
        except OSError:
            continue
        if ob not in b:
            continue
        lines = []
        for i, line in enumerate(b.decode('utf-8', errors='replace').splitlines(), 1):
            if old in line:
                lines.append((i, line.strip()))
        edits.append((r, b.count(ob), lines))
    return renames, edits


def report_plan(root, old, new, renames, edits, include_logs):
    print(f"from : {old}\nto   : {new}")
    print(f"logs : {'INCLUDED' if include_logs else 'excluded (not edited)'}\n")
    print(f"=== {len(renames)} path rename(s) ===")
    for s, d in renames:
        print(f"   {rel(root,s)}\n     -> {os.path.basename(d)}")
    if not renames:
        print("   none")
    total = sum(c for _, c, _ in edits)
    print(f"\n=== {len(edits)} file(s) to edit, {total} occurrence(s) ===")
    for r, c, lines in edits:
        print(f"   {r}  ({c})")
        for i, l in lines:
            print(f"      line {i}: {l[:130]}")
    if not edits:
        print("   none")
    # what is deliberately left alone
    skipped = []
    for p in walk(root):
        r = rel(root, p)
        if in_logs(r) and not include_logs:
            try:
                if old.encode() in open(p, 'rb').read():
                    skipped.append(r)
            except OSError:
                pass
    if skipped:
        print(f"\n=== {len(skipped)} file(s) under {LOGDIR}/ contain the old id and were NOT touched ===")
        for r in skipped[:10]:
            print("   ", r)
        print("   (re-run without --keep-logs if these should change)")


def apply(root, olds, new, include_logs):
    """Swap every id in olds to new, one after another, on the same tree."""
    before = manifest(root)
    ob_edits, all_renames, edited = [], [], set()
    nb = new.encode()
    for old in olds:
        renames, edits = find_changes(root, old, new, include_logs)
        ob = old.encode()
        for r, _, _ in edits:
            p = os.path.join(root, r)
            b = open(p, 'rb').read()
            open(p, 'wb').write(b.replace(ob, nb))
        for src, dst in renames:
            os.rename(src, dst)
            if src == root:
                root = dst
        ob_edits += edits
        all_renames += renames
        edited |= {r for r, _, _ in edits}
    after = manifest(root)

    # account for files whose path changed due to a parent rename
    moved = {k for k in before if k not in after}
    unexpected = [k for k in before
                  if k in after and before[k] != after[k] and k not in edited]
    return before, after, ob_edits, all_renames, moved, unexpected, root


def identity(root):
    """The three places a package declares its UUID."""
    folder = next(iter(HEX32.findall(os.path.basename(root))), None)

    toml_id, toml_line = None, None
    tp = os.path.join(root, 'task.toml')
    if os.path.isfile(tp):
        for i, line in enumerate(open(tp, encoding='utf-8', errors='replace'), 1):
            if line.lstrip().startswith('name'):
                found = HEX32.findall(line)
                if found:
                    toml_id, toml_line = found[0], i
                break

    trials = {}
    ld = os.path.join(root, LOGDIR)
    if os.path.isdir(ld):
        for dp, dn, _ in os.walk(ld):
            for d in sorted(dn):
                got = HEX32.findall(d)
                if got:
                    trials[os.path.relpath(os.path.join(dp, d), ld)] = got[0]
    return folder, toml_id, toml_line, trials


def wrong_ids(root, client):
    """Ids the package declares (folder, task.toml, trial dirs) that are not the client's."""
    folder, toml_id, _, trials = identity(root)
    declared = [folder, toml_id] + [trials[k] for k in sorted(trials)]
    return list(dict.fromkeys(m for m in declared if m and m != client))


def _show(items, limit=6):
    for it in items[:limit]:
        print(f"        {it}")
    if len(items) > limit:
        print(f"        ... and {len(items)-limit} more")


def check(root, client=None):
    """The rule: ONE uuid, consistent everywhere in the package, and (when the
    client's uuid is given) it must be the client's. Returns 0 if so, 1 if not."""
    folder, toml_id, toml_line, trials = identity(root)
    names, content, where = scan(root)
    allids = sorted(set(names) | set(content))
    logids = sorted(set(trials.values()))

    print("Declared identity")
    if client:
        print(f"   client uuid         : {client}")
    print(f"   package folder      : {folder or '(none found)'}")
    print(f"   task.toml name      : {toml_id or '(none found)'}"
          + (f"   (line {toml_line})" if toml_line else ""))
    if trials:
        for k, v in sorted(trials.items()):
            print(f"   {LOGDIR}/{k.split(os.sep)[0]:<28}: {v}")
    else:
        print(f"   {LOGDIR}/             : (no trial directories found)")

    problems = []
    if not folder:
        problems.append("package folder name contains no 32-hex uuid")
    if not toml_id:
        problems.append("task.toml has no uuid in its name field")
    if folder and toml_id and folder != toml_id:
        problems.append(f"folder name ({folder}) != task.toml name ({toml_id})")
    if len(logids) > 1:
        problems.append(f"execution logs disagree with each other: {logids}")
    if folder and logids and folder not in logids:
        problems.append(f"package ({folder}) != execution logs ({', '.join(logids)})")

    # the client's uuid: every declaration and every log must carry it
    if client:
        if client not in allids:
            problems.append(f"the client's uuid {client} does not appear anywhere in the package")
        if folder and folder != client:
            problems.append(f"package folder carries {folder}, not the client's uuid")
        if toml_id and toml_id != client:
            problems.append(f"task.toml (line {toml_line}) carries {toml_id}, not the client's uuid")
        bad_trials = sorted(f"{LOGDIR}/{k}  ({v})" for k, v in trials.items() if v != client)
        if bad_trials:
            problems.append(f"{len(bad_trials)} execution_logs trial dir(s) carry a uuid "
                            f"other than the client's")
        bad_logs = sorted({loc.split(': ', 1)[1] for m in allids if m != client
                           for loc in where[m] if in_logs(loc.split(': ', 1)[1])})
        if bad_logs:
            problems.append(f"{len(bad_logs)} path(s) under execution_logs/ carry a uuid "
                            f"other than the client's")
        if bad_trials:
            print("\nTrial dirs not on the client's uuid:")
            _show(bad_trials)
        if bad_logs:
            print("\nLogs not on the client's uuid (names or contents):")
            _show(bad_logs)

    # exactly one identifier across the whole package
    if len(allids) > 1:
        print(f"\n{len(allids)} different uuids present in this package:")
        for m in allids:
            locs = sorted(where[m])
            tag = "  <- client" if m == client else ""
            print(f"   {m}   names={names.get(m,0):<4} contents={content.get(m,0):<5}{tag}")
            _show(locs)
        problems.append(f"{len(allids)} uuids present; a package must carry exactly one")

    print()
    if problems:
        print("FAIL")
        for pr in problems:
            print("   -", pr)
        if not client:
            print("\n   re-run with --client <the client's uuid> to check against it and get "
                  "the exact fix command")
            return 1
        wrong = wrong_ids(root, client)
        other = [m for m in allids if m != client and m not in wrong]
        if wrong:
            froms = ' '.join(f'--from {w}' for w in wrong)
            print(f"\n   swap to the client's uuid {client}:")
            print(f"   fix: python3 uuid_swap.py apply <pkg> {froms} --to {client} --zip out.zip")
        if other:
            print("\n   also present, not declared as the package id (could be a hash or a"
                  " trace id):")
            for m in other:
                print(f"      {m}   if it is a task uuid, add --from {m} to the fix command")
        return 1
    if client:
        print(f"PASS  one uuid throughout, and it is the client's: {client}")
    else:
        print(f"PASS  one uuid throughout: {folder}")
        print("      (not compared with the client's uuid; pass --client to do that)")
    return 0


ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)   # fixed timestamp -> reproducible archives


def write_zip(root, out):
    """Write a byte-reproducible zip: sorted entries, fixed mtimes, original permissions."""
    base = os.path.basename(root)
    paths = sorted(rel(root, p) for p in walk(root))
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        for r in paths:
            src = os.path.join(root, r)
            zi = zipfile.ZipInfo(os.path.join(base, r).replace(os.sep, '/'), ZIP_EPOCH)
            zi.create_system = 3   # unix, so unzip honours the mode bits
            zi.external_attr = (stat.S_IFREG | stat.S_IMODE(os.stat(src).st_mode)) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(src, 'rb') as f:
                z.writestr(zi, f.read())
    return out


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def materialise(src, workdir):
    """Return a path to a writable package root copied from src (.zip or dir)."""
    if os.path.isdir(src):
        dst = os.path.join(workdir, os.path.basename(src.rstrip('/')))
        shutil.copytree(src, dst)
        return dst
    if not zipfile.is_zipfile(src):
        sys.exit(f"not a directory or zip: {src}")
    ex = os.path.join(workdir, '_x')
    with zipfile.ZipFile(src) as z:
        z.extractall(ex)
        # extractall drops permissions: restore them from the archive
        top = os.path.realpath(ex) + os.sep
        for info in z.infolist():
            mode = stat.S_IMODE(info.external_attr >> 16)
            if not mode or info.is_dir():
                continue
            p = os.path.realpath(os.path.join(ex, info.filename))
            if p.startswith(top) and os.path.isfile(p):
                os.chmod(p, mode)
    tops = [d for d in os.listdir(ex) if not d.startswith(('.', '__MACOSX'))]
    tops = [d for d in tops if os.path.isdir(os.path.join(ex, d))]
    if len(tops) != 1:
        sys.exit(f"expected exactly one top-level folder in the zip, found: {tops}")
    return os.path.join(ex, tops[0])


def _clean_path(raw):
    """Accept a drag-and-dropped path: quotes, backslash escapes, ~, stray spaces."""
    t = raw.strip()
    if len(t) > 1 and t[0] == t[-1] and t[0] in "\"'":
        t = t[1:-1]
    t = t.replace('\\ ', ' ').replace('\\~', '~')
    return os.path.expanduser(t.strip())


def _ask(prompt, default=None):
    sfx = f" [{default}]" if default else ""
    try:
        v = input(f"{prompt}{sfx}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\naborted."); sys.exit(1)
    return v or (default or "")


def _ask_client(prompt="Client's uuid (the one the client already holds)"):
    while True:
        c = norm_uuid(_ask(prompt))
        if c:
            return c
        print("  that is not a uuid (32 hex characters, dashes allowed)")


def interactive():
    print("=" * 68)
    print(" TaskPack Integrity: task UUID repair")
    print("=" * 68)

    while True:
        src = _clean_path(_ask("\nPath to the task zip (or folder)"))
        if src and os.path.exists(src):
            break
        print(f"  not found: {src!r}  (tip: you can drag the file into this window)")

    client = _ask_client("\nClient's uuid (the one the client already holds)")

    work = tempfile.mkdtemp(prefix='uuidswap_')
    try:
        print("\nreading package ...")
        root = materialise(src, work)
        print()
        check(root, client)
        print()
        names, content, where = scan(root)
        allids = sorted(set(names) | set(content))
        if not allids:
            print("No 32-hex identifiers found in this package."); return

        wrong = wrong_ids(root, client)
        other = [m for m in allids if m != client and m not in wrong]
        if not wrong and not other:
            print(f"The package already carries only the client's uuid {client}. Nothing to do.")
            return
        if wrong:
            print("Not the client's uuid, declared as the package id (folder, task.toml or logs):")
            for m in wrong:
                print(f"   {m}   names={names.get(m,0):<4} contents={content.get(m,0):<5}")
        if other:
            print("Also present, but not declared as the package id (could be a hash or trace id):")
            for m in other:
                print(f"   {m}   names={names.get(m,0):<4} contents={content.get(m,0):<5}")

        olds = parse_ids([_ask(f"\nUUID(s) to change to the client's {client} (comma-separated)",
                               ','.join(wrong))])
        if not olds:
            print("  nothing selected, nothing to do."); return
        for old in olds:
            if not HEX32.fullmatch(old) or old not in allids:
                print(f"  {old} is not present in this package."); return
        if client in olds:
            print("  that is the client's uuid itself; leave it out."); return
        inc = not _ask("Keep execution_logs unchanged? (y/N)", "N").lower().startswith('y')

        print("\n" + "-" * 68)
        for old in olds:
            renames, edits = find_changes(root, old, client, inc)
            report_plan(root, old, client, renames, edits, inc)
            print("-" * 68)

        if not _ask("\nApply these changes? (y/N)", "N").lower().startswith('y'):
            print("not applied. nothing was written."); return

        before, after, edits, renames, moved, unexpected, root = apply(root, olds, client, inc)
        if not edits and not renames:
            print("\nNothing to change."); return
        print(f"\n   files edited  : {len(edits)}")
        print(f"   paths renamed : {len(renames)}")
        print(f"   files total   : {len(before)} before, {len(after)} after")
        if unexpected:
            print(f"   !! {len(unexpected)} file(s) changed unexpectedly:")
            for u in unexpected: print("      ", u)
        else:
            print("   verified: nothing else changed")

        print("\nchecking the result against the client's uuid ...\n")
        check(root, client)

        base = os.path.dirname(os.path.abspath(src))
        default_out = os.path.join(base, os.path.basename(root) + '.zip')
        out = _clean_path(_ask("\nWrite zip to", default_out))
        if os.path.exists(out):
            if not _ask(f"  {os.path.basename(out)} exists. Overwrite? (y/N)", "N").lower().startswith('y'):
                print("  not written."); return
        os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
        write_zip(root, out)
        print(f"\n   zip    : {out}")
        print(f"   sha256 : {sha256_file(out)}")
        print("\nDone. Run the static gate on this zip before delivering.")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    if len(sys.argv) == 1:
        interactive(); return
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('mode', choices=['check', 'scan', 'plan', 'apply'])
    ap.add_argument('package', help='task package: a .zip or an extracted directory')
    ap.add_argument('--client', help="check: the client's uuid; every folder, task.toml and "
                                     "log must carry it (asked for when run in a terminal)")
    ap.add_argument('--from', dest='old', action='append',
                    help='uuid to replace; repeat it or comma-separate to swap several')
    ap.add_argument('--to', dest='new', help="the client's uuid to swap to")
    ap.add_argument('--keep-logs', action='store_true',
                    help='do NOT rewrite ids under execution_logs/ (default: rewrite them, '
                         "so the package carries the client's uuid throughout)")
    # older versions refused to rewrite the logs' uuid without --force; accepted, no effect
    ap.add_argument('--force', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--zip', dest='zipout',
                    help='write a reproducible zip of the result to this path')
    a = ap.parse_args()

    src = os.path.abspath(a.package.rstrip('/'))
    if not os.path.exists(src):
        sys.exit(f"no such path: {src}")

    work = tempfile.mkdtemp(prefix='uuidswap_')
    try:
        _run(a, src, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _run(a, src, work):
    # scan and plan are read-only: use the source directly when it is a directory
    if a.mode in ('scan', 'plan') and os.path.isdir(src):
        root = src
    else:
        root = materialise(src, work)

    if a.mode == 'check':
        client = None
        if a.client:
            client = norm_uuid(a.client)
            if not client:
                sys.exit(f"--client must be a uuid (32 hex characters), got: {a.client!r}")
        elif sys.stdin.isatty():
            raw = _ask("Client's uuid (Enter to skip)")
            if raw:
                client = norm_uuid(raw)
                if not client:
                    sys.exit(f"not a uuid: {raw!r}")
            print()
        sys.exit(check(root, client))

    if a.mode == 'scan':
        names, content, where = scan(root)
        print("=== 32-hex identifiers in PATH NAMES ===")
        for k, v in names.most_common() or [(None, None)]:
            print(f"   {v:6d}  {k}" if k else "   none")
        print("\n=== 32-hex identifiers in FILE CONTENTS ===")
        for k, v in content.most_common() or [(None, None)]:
            print(f"   {v:6d}  {k}" if k else "   none")
        for k in sorted(set(names) | set(content)):
            locs = sorted(where[k])
            print(f"\n--- {k}  ({len(locs)} location(s)) ---")
            for l in locs[:14]:
                print("   ", l)
            if len(locs) > 14:
                print(f"    ... and {len(locs)-14} more")
        return

    olds = parse_ids(a.old)
    if not olds or not a.new:
        sys.exit("--from and --to are required for plan/apply")
    new = norm_uuid(a.new)
    if not new:
        sys.exit(f"--to must be a uuid (32 hex characters), got: {a.new!r}")
    if new in olds:
        sys.exit("--from and --to are identical")

    names, content, _ = scan(root)
    for old in olds:
        if old not in names and old not in content:
            sys.exit(f"--from id not found anywhere in the package: {old}")
    if new in names or new in content:
        print(f"NOTE: {new} is already present in this package "
              f"(names={names.get(new,0)}, contents={content.get(new,0)}).\n"
              f"      That is expected when part of the package already carries the client's uuid.\n")

    _f, _t, _tl, _trials = identity(root)
    _logids = set(_trials.values())
    include_logs = not a.keep_logs
    for old in olds:
        if old in _logids and include_logs:
            print(f"NOTE: {old} is the uuid the runs were executed under. The execution logs "
                  f"are rewritten to {new} too, so the package carries the client's uuid "
                  f"throughout.\n")

    for old in olds:
        renames, edits = find_changes(root, old, new, include_logs)
        report_plan(root, old, new, renames, edits, include_logs)
        if len(olds) > 1:
            print()
    if a.mode == 'plan':
        return

    before, after, edits, renames, moved, unexpected, root = apply(root, olds, new, include_logs)
    print("\n=== applied ===")
    print(f"   files edited   : {len(edits)}")
    print(f"   paths renamed  : {len(renames)}")
    print(f"   files total    : {len(before)} before, {len(after)} after")
    print(f"   content changed unexpectedly: {len(unexpected)}")
    for u in unexpected:
        print("      !!", u)
    if not unexpected:
        print("   verified: no file changed except the ones listed above")

    if a.zipout:
        out = os.path.abspath(a.zipout)
        os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
        write_zip(root, out)
        print(f"\n   zip    : {out}")
        print(f"   sha256 : {sha256_file(out)}")
        print(f"   (reproducible: the same command yields a byte-identical zip)")


if __name__ == '__main__':
    main()
