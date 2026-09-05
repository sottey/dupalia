# dupalia

`dupalia` is a read-only Ubuntu/Linux command-line inventory tool. It recursively records regular files from one or more directories to a CSV so inventories from several machines can later be compared for storage analysis and duplicate detection.

It never changes, moves, deletes, renames, synchronizes, or otherwise modifies scanned files. It reads metadata and, unless disabled, streams file contents to calculate SHA-256 hashes.

## Build

```bash
go build -o dupalia .
```

## Usage

```bash
./dupalia --output strongbox.csv /mnt/orestack /mnt/bigboi
./dupalia --no-hash --output metadata.csv /mnt/orestack
./dupalia --cross-filesystems --workers 2 /mnt/storage
```

Flags:

- `--output PATH`: destination CSV. Defaults to `dupalia-<hostname>.csv`.
- `--no-hash`: do not read contents; `sha256` is blank and `hash_status` is `skipped`.
- `--cross-filesystems`: include nested mounted filesystems. By default, each root stays on its starting device.
- `--workers N`: bounded hashing workers; default `1`, and values below 1 are rejected. `--workers 1` is the safest choice for spinning disks and RAID arrays.
- `--progress-every N`: report progress every N discovered files; default `10000`, or `0` to disable.

Symlinks and all non-regular special files are skipped. Overlapping or duplicate roots are rejected before scanning. If a file cannot be fully hashed or changes during hashing, its row remains in the CSV with a blank hash and `read_error` status. If interrupted, rows already written remain a valid CSV inventory.

For the read-only guarantee, the output CSV must be outside every scan root; `dupalia` rejects an output path inside a scanned directory. Ctrl-C and SIGTERM stop traversal, interrupt hashing at the next 1 MiB streaming chunk, flush the partial CSV, and return a non-zero exit status.

## CSV schema

The header is always:

```text
hostname,scan_root,relative_path,full_path,filename,extension,size_bytes,modified_time,created_time,mode,uid,gid,inode,device,sha256,hash_status
```

`hostname` identifies the scanning machine; `scan_root` is the supplied absolute cleaned root; `relative_path` is relative to that root; and `full_path` is its absolute path. `filename` is the basename and `extension` is the lowercase final extension without a dot. `size_bytes` is raw bytes, `modified_time` is RFC3339Nano, and `created_time` is blank when a reliable Linux creation time is not available. `mode`, `uid`, `gid`, `inode`, and `device` are Unix metadata.

`sha256` is the lowercase SHA-256 digest of the full content when successful. `hash_status` is `ok`, `skipped`, or `read_error`.
