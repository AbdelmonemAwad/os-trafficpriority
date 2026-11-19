#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""hardware.py: which classes have a place in the switch's queues on an XGS appliance, which queue
each takes, the ports' scheduling and the chip's weights - against classes written here as config.xml
holds them. The two places in the page's order, a DSCP shared by its classes, Best Effort, IPv6 alone
and a class switched off left out; a class without a minimum strict and in the top queues, one with a
minimum weighted below them; the minimums taken while they add up to 100 at most and held only by a
class with a place; Firewall: Shaper's parts taken after the minimums, while they fit; and the weight
sequence - each queue its share of turns, queue 0 the rest, every queue at least once, no more than
the chip's 128. The same cases as tools/test-mvc.php gives the model's refusals at the save.

    python3 tools/test-hardware.py"""
import os
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'trafficpriority'))
import hardware  # noqa: E402

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


def cls(uuid, dscp='46', sequence='100', minimum='', enabled='1', ipprotocol='inet'):
    return {'uuid': uuid, 'enabled': enabled, 'sequence': sequence, 'dscp': dscp, 'minimum': minimum,
            'ipprotocol': ipprotocol}


def queues(plan):
    return {d['dscp']: (d['queue'], d['kind'], d['percent']) for d in plan['dscps']}


def counts(seq):
    return {q: seq.count(q) for q in range(7, -1, -1)}


# ---- places ----
taken, why = hardware.places([cls('a', '46'), cls('b', '34'), cls('c', '40')])
check('places: the first two DSCPs in the list\'s order; the third pf only', (taken, why),
      ([46, 34], {'a': 'hardware', 'b': 'hardware', 'c': 'third'}))
taken, why = hardware.places([cls('a', '46', '300'), cls('b', '34', '200'), cls('c', '40', '100')])
check('places: by sequence, not by where they are listed', (taken, why['a']), ([40, 34], 'third'))
taken, why = hardware.places([cls('a', '46', '100'), cls('b', '34', '100'), cls('c', '40', '100')])
check('places: the same sequence - as listed', taken, [46, 34])
taken, why = hardware.places([cls('a', '46'), cls('b', '46'), cls('c', '34'), cls('d', '40')])
check('places: two classes of one DSCP share its place', (taken, why['b'], why['d']), ([46, 34], 'hardware', 'third'))
taken, why = hardware.places([cls('a', '0'), cls('b', '46', ipprotocol='inet6'), cls('c', '34', enabled='0'),
                              cls('d', 'x'), cls('e', '34'), cls('f', '10', ipprotocol='inet46')])
check('places: Best Effort, IPv6 alone, a class switched off and a DSCP not readable take none',
      (taken, why), ([34, 10], {'a': 'best-effort', 'b': 'ipv6', 'c': 'off', 'd': 'dscp', 'e': 'hardware',
                                'f': 'hardware'}))
check('places: a sequence not readable goes last', hardware.places([cls('a', '46', '1'), cls('b', '34', 'x'),
                                                                    cls('c', '40', '2')])[0], [46, 40])
check('places: an empty enabled element is off, as the rules hook reads it',
      hardware.places([cls('a', '46', enabled='')])[1], {'a': 'off'})

# ---- plan ----
p = hardware.plan([cls('a', '46')])
check('one class, no minimum: queue 7 strict, the ports strict for queue 7 (mode 1), the weights as found',
      (queues(p), p['mode'], p['weights']), ({46: (7, 'strict', None)}, 1, None))
p = hardware.plan([cls('a', '46'), cls('b', '34')])
check('two strict: queues 7 and 6, mode 2', (queues(p), p['mode']), ({46: (7, 'strict', None), 34: (6, 'strict', None)}, 2))
p = hardware.plan([cls('a', '46', minimum='30')])
check('one class with a minimum: weighted, all weighted (mode 0), 30 turns against 70 for queue 0',
      (queues(p), p['mode'], counts(p['weights'])),
      ({46: (7, 'weighted', 30)}, 0, {7: 30, 6: 1, 5: 1, 4: 1, 3: 1, 2: 1, 1: 1, 0: 70}))
p = hardware.plan([cls('a', '34', minimum='30'), cls('b', '46')])
check('a minimum first in the list and a strict class after it: the strict one takes queue 7 and goes first',
      (queues(p), p['mode'], counts(p['weights'])[6], counts(p['weights'])[0]),
      ({46: (7, 'strict', None), 34: (6, 'weighted', 30)}, 1, 30, 70))
p = hardware.plan([cls('a', '46', minimum='20'), cls('b', '34', minimum='30')])
check('two minimums: queues 7 and 6 weighted, mode 0; 20, 30 and the rest, 50',
      (queues(p), p['mode'], counts(p['weights'])),
      ({46: (7, 'weighted', 20), 34: (6, 'weighted', 30)}, 0, {7: 20, 6: 30, 5: 1, 4: 1, 3: 1, 2: 1, 1: 1, 0: 50}))
p = hardware.plan([cls('a', '46', minimum='20'), cls('b', '46', minimum='15'), cls('c', '46')])
check('three classes of one DSCP: one queue, their minimums added',
      (queues(p), p['classes']['c']['queue'], p['classes']['c']['kind'], p['dscps'][0]['classes']),
      ({46: (7, 'weighted', 35)}, 7, 'weighted', ['a', 'b', 'c']))
p = hardware.plan([cls('a', '46', minimum='60'), cls('b', '34', minimum='50')])
check('minimums past 100: the later one not held, its class strict - and so on top, queue 7',
      (queues(p), p['classes']['b']['minimum_why'], p['classes']['a']['minimum_why'], p['mode']),
      ({46: (6, 'weighted', 60), 34: (7, 'strict', None)}, 'over', '', 1))
p = hardware.plan([cls('a', '46'), cls('b', '34'), cls('c', '40', minimum='20')])
check('a minimum on a third DSCP: not held - no queue of its own',
      (p['classes']['c']['why'], p['classes']['c']['minimum_why'], p['weights']), ('third', 'not-hardware', None))
p = hardware.plan([cls('a', '0', minimum='20'), cls('b', '46', minimum='10', ipprotocol='inet6')])
check('a minimum on Best Effort or IPv6 alone: not held', [p['classes'][u]['minimum_why'] for u in 'ab'],
      ['not-hardware', 'not-hardware'])
p = hardware.plan([cls('a', '46', minimum='20', enabled='0'), cls('b', '34')])
check('a class switched off: no place, and its minimum nothing', (queues(p), p['classes']['a']['minimum_why']),
      ({34: (7, 'strict', None)}, ''))
for bad in ('0', '101', 'x', '-5', '1000'):
    check('a minimum of %r is none' % bad, hardware.plan([cls('a', '46', minimum=bad)])['dscps'][0]['kind'], 'strict')
p = hardware.plan([cls('a', '46', minimum='100')])
check('a minimum of 100: queue 0 still one turn, as every queue',
      counts(p['weights']), {7: 100, 6: 1, 5: 1, 4: 1, 3: 1, 2: 1, 1: 1, 0: 1})
p = hardware.plan([])
check('no class: nothing for the switch', (p['dscps'], p['mode'], p['weights']), ([], None, None))

# ---- Firewall: Shaper's parts ----
p = hardware.plan([cls('a', '46'), cls('b', '34')], {46: 70})
check('a part from Firewall: Shaper: weighted, taken where no minimum is', (queues(p), p['dscps'][0]['from']),
      ({46: (6, 'weighted', 70), 34: (7, 'strict', None)}, 'shaper'))
p = hardware.plan([cls('a', '46', minimum='20')], {46: 70})
check('a class\'s own minimum before a part from Firewall: Shaper', (queues(p), p['dscps'][0]['from']),
      ({46: (7, 'weighted', 20)}, 'minimum'))
p = hardware.plan([cls('a', '46', minimum='50'), cls('b', '34')], {34: 70})
check('a part that would take the parts past 100: not taken', queues(p)[34], (7, 'strict', None))
p = hardware.plan([cls('a', '46')], {34: 50})
check('a part for a DSCP with no place: nothing', queues(p), {46: (7, 'strict', None)})

# ---- the weight sequence ----
seq = hardware.turns({7: 33, 6: 25, 5: 17, 4: 12, 3: 6, 2: 3, 1: 2})
check('turns: UMSD\'s default weights as shares, the 2 left to queue 0 - 100 turns', (len(seq), counts(seq)),
      (100, {7: 33, 6: 25, 5: 17, 4: 12, 3: 6, 2: 3, 1: 2, 0: 2}))
seq = hardware.turns({7: 50})
check('turns: spread - no queue twice in a row at a half', all(seq[i] != seq[i + 1] or seq[i] == 0
                                                               for i in range(len(seq) - 1)), True)
check('turns: every queue at least once, never more than 128', all(
    min(counts(hardware.turns({7: a, 6: b})).values()) >= 1 and len(hardware.turns({7: a, 6: b})) <= 128
    for a in (1, 30, 99, 100) for b in (0, 1, 50) if a + b <= 100), True)
try:
    hardware.turns({7: 100, 6: 100})
    check('turns: more than the chip holds refused', False, True)
except ValueError:
    check('turns: more than the chip holds refused', True, True)

# ---- config.xml ----
root = ET.fromstring('<opnsense><OPNsense><TrafficPriority><general><enabled>1</enabled><follow_shaper>1</follow_shaper>'
                     '</general><classes><class uuid="ABC"><enabled>1</enabled><dscp>46</dscp><minimum>25</minimum>'
                     '</class></classes></TrafficPriority></OPNsense></opnsense>')
on, follow, classes = hardware.read_classes(root)
check('config.xml: on, following Firewall: Shaper, the class with its UUID in lower case',
      (on, follow, classes[0]['uuid'], classes[0]['minimum']), (True, True, 'abc', '25'))
check('config.xml: never set: off, nothing', hardware.read_classes(ET.fromstring('<opnsense/>')), (False, False, []))

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
