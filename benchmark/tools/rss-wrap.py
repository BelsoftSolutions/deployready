#!/usr/bin/env python3
"""Run a command with inherited stdio and write the peak RSS of it and its descendants (KB) to a file.
usage: rss-wrap.py <rss-out-file> <cmd> [args...]"""
import resource
import subprocess
import sys
import time

out = sys.argv[1]
t0 = time.time()
rc = subprocess.call(sys.argv[2:])
ru = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
kb = ru // 1024 if sys.platform == "darwin" else ru
with open(out, "w") as f:
    f.write("%d %d" % (kb, int((time.time() - t0) * 1000)))
sys.exit(rc)
