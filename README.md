# TaskPack Integrity

A dependency-free Python CLI for inspecting and repairing UUID references across task-package directories and ZIP archives.

Task packages can drift when a directory is renamed but its manifest or associated artifacts still contain an earlier identifier. TaskPack Integrity separates **scan → plan → apply → check** so you can review identifier changes, write a repaired copy, and validate the result.

## Quick start

Requires Python 3.10 or newer. No third-party runtime dependencies or account credentials are needed.

```sh
python3 uuid_swap.py --help
python3 uuid_swap.py scan examples/11111111111111111111111111111111-DEMO
python3 uuid_swap.py check examples/11111111111111111111111111111111-DEMO \
  --client 11111111111111111111111111111111
```

Preview a repair, write a new archive, then check it:

```sh
python3 uuid_swap.py plan examples/11111111111111111111111111111111-DEMO \
  --from 11111111111111111111111111111111 \
  --to 22222222222222222222222222222222

python3 uuid_swap.py apply examples/11111111111111111111111111111111-DEMO \
  --from 11111111111111111111111111111111 \
  --to 22222222222222222222222222222222 \
  --zip repaired.zip --require-check

python3 uuid_swap.py check repaired.zip \
  --client 22222222222222222222222222222222
```

The UUIDs and files in `examples/` are synthetic. `--client` means the expected canonical package UUID; it does not contact any service.

Optional installation exposes a `taskpack-integrity` command with the same arguments:

```sh
python3 -m pip install .
taskpack-integrity --help
```

Running `python3 uuid_swap.py` without arguments starts an interactive workflow that previews changes and asks for confirmation before writing an archive.

## Commands

| Command | Behavior |
| --- | --- |
| `scan PACKAGE` | Lists detected 32-character lowercase hexadecimal identifiers in paths and file contents. |
| `plan PACKAGE --from OLD --to NEW` | Reports proposed path renames and byte replacements without changing the input. |
| `apply PACKAGE --from OLD --to NEW --zip OUTPUT` | Applies changes to a temporary copy and writes a new ZIP archive. |
| `check PACKAGE --client EXPECTED` | Checks identity consistency against an explicitly supplied expected UUID. |

`PACKAGE` accepts a directory or a ZIP containing a single top-level package directory. Repeat `--from` or pass comma-separated identifiers to consolidate multiple old identifiers. `--keep-logs` excludes `execution_logs/` from repairs; the resulting package may therefore still fail a consistency check.

`apply` requires `--zip OUTPUT`; it refuses to silently discard a repaired working copy. Existing output archives are refused unless `--overwrite` is supplied. Output cannot replace the input archive or be written inside the source directory. In non-interactive use, omitting `--client` checks internal consistency only, not whether the identifier is the intended one. Exit status `0` indicates a successful command/check; failed checks and invalid inputs return nonzero.

## What is implemented

- Input packages are copied before repair; the original package is not edited.
- Repair preflight rejects file/directory rename collisions, including case-insensitive destination collisions.
- Integrity verification compares every output file byte-for-byte against the expected replacements, tracks renamed paths, checks permissions, and preserves empty directories. SHA-256 manifests summarize file contents.
- Output is built in a temporary file beside the destination and published atomically after writing completes; a failed write leaves an existing output untouched.
- ZIP entries use sorted paths and fixed timestamps for repeatable output with the same input and runtime/compression implementation.
- Unix file permission bits are retained in output archives, including executable scripts.
- The test suite constructs synthetic packages and exercises both directory and ZIP workflows.

## Verification

```sh
python3 -I test_uuid_swap.py
python3 -m unittest discover -s tests -v
```

The original CLI integration checks cover manifest/path changes, identifier consistency, multiple source identifiers, log inclusion/exclusion, interactive confirmation, executable modes, reproducible archives, and malformed target identifiers. Additional release and safety checks verify input immutability, unchanged unrelated files, the packaged command entry point, collision refusal, output overwrite protection, unsafe/corrupt ZIP rejection, extraction limits, symlink rejection, empty directory preservation, injected write failures, structured reports, and post-repair validation. GitHub Actions runs these checks on Linux and macOS.

## Automation and safe output

```sh
taskpack-integrity scan PACKAGE --json
taskpack-integrity plan PACKAGE --from OLD --to NEW --json
taskpack-integrity apply PACKAGE --from OLD --to NEW \
  --zip repaired.zip --require-check --json
taskpack-integrity check repaired.zip --client NEW --json
```

Replace `PACKAGE`, `OLD`, and `NEW` with your package path and identifiers. All four commands support `--json`, which emits one object with `command`, `success`, `exit_code`, `error`, `result`, and human-readable `messages`. Scan results contain identifier counts and locations; checks include declared identities; successful repairs include the output path, SHA-256, file counts, rename/edit counts, and verification status. CLI syntax errors detected by the argument parser still use its standard stderr usage output.

`--require-check` validates the repaired package against `--to` before publishing it. For example, unrelated 32-hex tokens left in the package or old identifiers retained by `--keep-logs` can fail this check; failure leaves the destination untouched. Without this flag, an authorized partial repair can be published, but every entry must still match the exact intended byte/path transformation. `--overwrite` permits atomic replacement of an existing destination after all requested checks pass. The interactive workflow continues to ask before overwriting an existing archive.

## Scope and limitations

This is an identifier-maintenance tool, not a general archive validator or proof of benchmark correctness. It does not run tasks, compare agent performance, or certify execution provenance. Only rewrite identifiers when authorized, and retain original artifacts when their identity matters for an audit.

- Inspection treats all matching 32-hex tokens as possible identifiers; hashes and trace IDs can therefore trigger a failed consistency check.
- Source-token discovery and replacement primarily target undashed lowercase identifiers; target UUID arguments accept dashed or uppercase forms and normalize them.
- Replacements are byte-based, including file contents; inspect the plan before applying them.
- The change report is not a complete semantic audit, and it does not prove that every file was interpreted correctly.
- ZIP extraction is streamed and bounded to 10,000 entries, 128 MiB per file, 512 MiB total uncompressed data, and a maximum 1,000:1 per-entry compression ratio. These are fixed safety limits, not a sandbox or malware scanner.
- Symlinks, special files, encrypted ZIP entries, unsafe paths, duplicate entries, and case-colliding ZIP paths are rejected. A ZIP must contain one package directory and no loose top-level files.
- Permissions and empty directories are preserved; ownership, ACLs, extended attributes, and original timestamps are not.
- Inspection and repair still load file contents into memory; directory inputs have no size quota. Use reasonably sized packages.
- Scripted repairs require a passing consistency check only when `--require-check` is supplied. Integrity verification always runs independently.
- Concurrent external modification of an input directory is unsupported; work from a stable snapshot.
- Atomic publication prevents partial destination archives for handled failures; a forced process termination can leave a temporary `.taskpack-*.zip` file.

## Repository layout

```text
uuid_swap.py          CLI and implementation
test_uuid_swap.py     Original synthetic integration checks
tests/                Additional release checks
examples/             Small synthetic package
.github/workflows/    CI configuration
```

## License

MIT. See [LICENSE](LICENSE).
