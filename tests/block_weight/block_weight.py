#!/usr/bin/env python
# Simulate a maximal block attack on the Monero network
# This uses the scheme proposed by ArticMine
# Written by Sarang Nother
# Copyright (c) 2019-2022, The Monero Project
from __future__ import print_function
import json
import os
import sys
import math

MEDIAN_WINDOW_SMALL = 100 # number of recent blocks for median computation
MEDIAN_WINDOW_BIG = 5000

# The short-term surge factor S is READ FROM THE CONSENSUS AUTHORITY, not
# written here. This file is the independent reference model that
# `compare.py` diffs against the C++ implementation, and the C++ side takes S
# from the same JSON through the generated header — so a literal here is a
# second copy of a consensus constant in a second language, which is how it
# came to say 50.0 after the ratified value became 4 (C2-R2 Q3, signed
# 2026-09-06) and made this differential fail for a reason that had nothing
# to do with the algorithms disagreeing.
#
# Reading the authority does NOT weaken the differential. Its value is that
# two independent implementations of the ArticMine weight ALGORITHM agree; S
# is a parameter, not part of the algorithm. Sharing the parameter removes a
# false-failure mode whose natural fix — edit the Python to match the C++ —
# is precisely the reflex that lets a real algorithmic divergence hide behind
# a "just re-sync the constant" commit.
def _surge_factor():
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, os.pardir, os.pardir, "config", "consensus_constants.json")
    with open(path) as handle:
        constants = json.load(handle)
    key = "block_weight_short_term_surge_factor"
    if key not in constants:
        # Assert the subject rather than defaulting: a silent fallback would
        # make this model disagree with consensus and report it as an
        # algorithm mismatch.
        raise KeyError("%s missing from %s" % (key, path))
    return float(constants[key])

MULTIPLIER_BIG = _surge_factor()
MEDIAN_THRESHOLD = 300*1000 # initial value for median (scaled kB -> B)
lcg_seed = 0
embw = MEDIAN_THRESHOLD
ltembw = MEDIAN_THRESHOLD

weights = [MEDIAN_THRESHOLD]*MEDIAN_WINDOW_SMALL # weights of recent blocks (B), with index -1 most recent
lt_weights = [MEDIAN_THRESHOLD]*MEDIAN_WINDOW_BIG # long-term weights

# Compute the median of a list
def get_median(vec):
    #temp = vec
    temp = sorted(vec)
    if len(temp) % 2 == 1:
        return temp[len(temp)//2]
    else:
        return int((temp[len(temp)//2]+temp[len(temp)//2-1])//2)

def LCG():
  global lcg_seed
  lcg_seed = (lcg_seed * 0x100000001b3 + 0xcbf29ce484222325) & 0xffffffff
  return lcg_seed

def run(t, blocks):
  global embw
  global ltembw

  weights = [MEDIAN_THRESHOLD]*MEDIAN_WINDOW_SMALL # weights of recent blocks (B), with index -1 most recent
  lt_weights = [MEDIAN_THRESHOLD]*MEDIAN_WINDOW_BIG # long-term weights

  for block in range(blocks):
      # determine the long-term effective weight
      ltmedian = get_median(lt_weights[-MEDIAN_WINDOW_BIG:])
      ltembw = max(MEDIAN_THRESHOLD,ltmedian)

      # determine the effective weight
      stmedian = get_median(weights[-MEDIAN_WINDOW_SMALL:])
      embw = min(max(MEDIAN_THRESHOLD,stmedian),int(MULTIPLIER_BIG*ltembw))

      # drop the lowest values
      weights = weights[1:]
      lt_weights = lt_weights[1:]

      # add a block of max weight
      if t == 0:
        max_weight = 2 * embw
      elif t == 1:
        r = LCG()
        max_weight = int(90 + r % 500000 + 250000 + math.sin(block / 200.) * 350000)
        if max_weight < 90: max_weight = 90
      elif t == 2:
        max_weight = 90
      else:
        sys.exit(1)
      weights.append(max_weight)
      # Keep the Python reference model aligned with
      # Blockchain::get_next_long_term_block_weight bounds:
      # [median * (10/17), median * (17/10)].
      bounded_weight = max(max_weight, int(ltembw * 10 / 17))
      lt_weights.append(min(bounded_weight, int(ltembw + int(ltembw * 7 / 10))))

      #print "H %u, r %u, BW %u, EMBW %u, LTBW %u, LTEMBW %u, ltmedian %u" % (block, r, max_weight, embw, lt_weights[-1], ltembw, ltmedian)
      print("H %u, BW %u, EMBW %u, LTBW %u" % (block, max_weight, embw, lt_weights[-1]))

run(0, 2 * MEDIAN_WINDOW_BIG)
run(1, 9 * MEDIAN_WINDOW_BIG)
run(2, 1 * MEDIAN_WINDOW_BIG)
