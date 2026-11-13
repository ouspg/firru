"""
Git-history plumbing: read blobs and list tree entries at arbitrary commits.

Generic helpers used to reconstruct declared state (e.g. policy trees) at a
past commit. No assumptions about repository contents.
"""

import subprocess


def git(repo, *args):
    """Run `git -C repo ...` and return stdout (text)."""
    return subprocess.run(
        ["git", "-C", repo, *args],
        check=True, capture_output=True, text=True,
    ).stdout


class BlobReader:
    """Persistent `git cat-file --batch` for fast blob reads."""

    def __init__(self, repo):
        self.proc = subprocess.Popen(
            ["git", "-C", repo, "cat-file", "--batch"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )

    def read(self, sha):
        self.proc.stdin.write((sha + "\n").encode())
        self.proc.stdin.flush()
        header = self.proc.stdout.readline().decode().strip()
        if header.endswith("missing"):
            return None
        size = int(header.split()[2])
        data = self.proc.stdout.read(size)
        self.proc.stdout.read(1)  # trailing newline
        return data

    def close(self):
        self.proc.stdin.close()
        self.proc.wait()


def list_blobs(repo, commit, path, suffix=".yml"):
    """[(sha, filename)] of `*suffix` blobs under path at commit."""
    try:
        out = git(repo, "ls-tree", "-r", commit, "--", path)
    except subprocess.CalledProcessError:
        return []
    blobs = []
    for line in out.splitlines():
        meta, name = line.split("\t", 1)
        if not name.endswith(suffix):
            continue
        blobs.append((meta.split()[2], name))
    return blobs
