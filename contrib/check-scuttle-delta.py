#!/usr/bin/env python3
"""Report the Git delta and reject growth of the reviewed upstream hunk budget."""

import json
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def git(*args):
	return subprocess.check_output(["git", *args], cwd=ROOT, text=True)


def upstream_hunks(upstream):
	files = set(git("ls-tree", "-r", "--name-only", upstream).splitlines())
	counts = {}
	current = None
	for line in git("diff", "--no-ext-diff", "--no-renames", "--unified=0", upstream).splitlines():
		if line.startswith("diff --git "):
			current = shlex.split(line)[2].removeprefix("a/")
		elif current in files and (line.startswith("@@ ") or line.startswith("Binary files ")):
			counts[current] = counts.get(current, 0) + 1
	return counts


def main():
	budget = json.loads((ROOT / "contrib/scuttle-upstream-hunks.json").read_text())
	actual = upstream_hunks(budget["upstream"])
	over = {path: {"actual": value, "budget": budget["per_file_hunks"].get(path, 0)}
		for path, value in actual.items() if value > budget["per_file_hunks"].get(path, 0)}
	print(json.dumps({"upstream": budget["upstream"], "head": git("rev-parse", "HEAD").strip(),
		"upstream_hunks": sum(actual.values()), "over_budget": over}, indent=2))
	print("Per-topic Git additions/deletions (includes tests, docs and generated files):", flush=True)
	subprocess.run(["git", "log", "--reverse", "--format=%h %s", "--shortstat",
		budget["upstream"] + "..HEAD"], cwd=ROOT, check=True)
	return bool(over)


if __name__ == "__main__":
	sys.exit(main())
