#!/usr/bin/env python

from __future__ import print_function
import sys
import subprocess
import re

if len(sys.argv) == 4:
  first = [sys.argv[1], sys.argv[2]]
  second = [sys.argv[3]]
else:
  first = [sys.argv[1]]
  second = [sys.argv[2]]

print('running: ', first)
S0 = subprocess.check_output(first, stderr=subprocess.STDOUT).decode("utf-8")
print('running: ', second)
S1 = subprocess.check_output(second, stderr=subprocess.STDOUT).decode("utf-8")
print('comparing')

line_re = re.compile(r'^H (\d+), BW (\d+), EMBW (\d+), LTBW (\d+)$')

def parse_rows(blob):
  rows = []
  for ln in blob.splitlines():
    m = line_re.match(ln.strip())
    if not m:
      raise ValueError('Unparseable line: %s' % ln)
    rows.append(tuple(int(g) for g in m.groups()))
  return rows

try:
  expected_rows = parse_rows(S0)
  actual_rows = parse_rows(S1)
except ValueError:
  # Fallback for unexpected format regressions.
  if S0 != S1:
    sys.exit(1)
  sys.exit(0)

if len(expected_rows) != len(actual_rows):
  print('row count mismatch: expected %d got %d' % (len(expected_rows), len(actual_rows)))
  sys.exit(1)

# HF1 design alignment:
# - block synthesis and long-term bounded weight must remain deterministic.
# - effective median must stay above the minimum full-reward zone floor.
MIN_EFFECTIVE_BLOCK_WEIGHT = 300000

for i, (exp, got) in enumerate(zip(expected_rows, actual_rows)):
  if exp[0] != got[0] or exp[1] != got[1] or exp[3] != got[3]:
    print('mismatch at row %d: expected=%s got=%s' % (i + 1, exp, got))
    sys.exit(1)
  if got[2] < MIN_EFFECTIVE_BLOCK_WEIGHT:
    print('invalid EMBW floor at row %d: %d < %d' % (i + 1, got[2], MIN_EFFECTIVE_BLOCK_WEIGHT))
    sys.exit(1)

sys.exit(0)
