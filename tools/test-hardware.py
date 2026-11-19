#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""hardware.py: which classes have a place in the switch's queues on an XGS appliance, which queue each
takes, the ports' scheduling and the chip's weights - against classes written here as config.xml holds
them, and the rules file the last filter reload wrote (the places are the rules that take a DSCP off
other traffic, which the rules hook writes for each; tools/test-rules.php holds the hook to its order).
A class whose rule the file does not hold has no place; Best Effort, the DSCPs below it, IPv6 alone and a
class switched off neither; a third DSCP is pf's alone. Strict classes in the top queues; minimums
weighted - and the two never mixed, nor minimums past 100: the switch is then given nothing, and why is
said. Firewall: Shaper's parts only where no class has a minimum, every place has one, and they fit.
And the weight sequence - each queue its share of turns, queue 0 the rest, every queue at least once, no
more than the chip's 128.

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


def plan(classes, places, shares=None, written=None):
    """The plan with every class's rule written, unless told which were."""
    return hardware.plan(classes, places, {c['uuid'] for c in classes} if written is None else written, shares)


def queues(p):
    return {d['dscp']: (d['queue'], d['kind'], d['percent']) for d in p['dscps']}


def counts(seq):
    return {q: seq.count(q) for q in range(7, -1, -1)}


U1 = '6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a01'
U2 = '6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a02'
U3 = '6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a03'

# ---- the places, from the rules file as OPNsense writes it ----
RULES = """# [prio: 0]
match in inet from {any} to {any} tos 0xb8 scrub ( set-tos 0x00 ) label "trafficpriority-clear-46" # Traffic Priority: DSCP 46 taken off other traffic
match in inet from {any} to {any} scrub ( set-tos 0x00 ) tos 0x88 label "trafficpriority-clear-34" # Traffic Priority: DSCP 34 taken off other traffic
match in on igb1 inet from {any} to {any} scrub ( set-tos 0x88 ) label "trafficpriority-%s" # Traffic Priority: Video
match in on igb1 inet from {any} to {any} scrub ( set-tos 0xb8 ) label "trafficpriority-%s" # Traffic Priority: Voice
#debug:Interface opt9 not found
# match in on ##opt9## inet from {any} to {any} scrub ( set-tos 0x88 ) label "trafficpriority-%s" # Traffic Priority: Gone
""" % (U2, U1, U3)
check('the places, in the rules file\'s order, and the classes it wrote a rule for - a rule commented out none',
      hardware.from_rules(RULES), ([46, 34], {U1, U2}))
check('a rules file with no place', hardware.from_rules('match in on igb1 inet scrub ( set-tos 0xb8 ) label '
                                                        '"trafficpriority-%s"' % U1), ([], {U1}))
check('no rules file', hardware.from_rules(''), ([], set()))

# ---- which class has a place ----
p = plan([cls('a', '46'), cls('b', '34'), cls('c', '40')], [46, 34])
check('two places taken; a third DSCP pf only', {u: r['why'] for u, r in p['classes'].items()},
      {'a': 'hardware', 'b': 'hardware', 'c': 'third'})
p = plan([cls('a', '46'), cls('b', '34')], [46])
check('a DSCP the last filter reload gave no place, one left: Apply puts it in', p['classes']['b']['why'], 'no-place')
p = plan([cls('a', '46'), cls('b', '34')], [46, 34], written={'b'})
check('a class whose rule the file does not hold: no place - and its DSCP not given to the switch',
      (p['classes']['a']['why'], [d['dscp'] for d in p['dscps']]), ('rule', [34]))
p = plan([cls('a', '0'), cls('b', '8'), cls('c', '46', ipprotocol='inet6'), cls('d', '34', enabled='0'),
          cls('e', 'x'), cls('f', '10', ipprotocol='inet46')], [10])
check('Best Effort, CS1 below it, IPv6 alone, a class switched off and a DSCP not readable take none',
      {u: r['why'] for u, r in p['classes'].items()},
      {'a': 'best-effort', 'b': 'below-default', 'c': 'ipv6', 'd': 'off', 'e': 'dscp', 'f': 'hardware'})
check('an empty enabled element is off, as the rules hook reads it',
      plan([cls('a', '46', enabled='')], [46])['classes']['a']['why'], 'off')

# ---- strict ----
p = plan([cls('a', '46')], [46])
check('one class, no minimum: queue 7 strict, the ports strict for queue 7 (mode 1), the weights as found',
      (queues(p), p['mode'], p['weights'], p['refused']), ({46: (7, 'strict', None)}, 1, None, ''))
p = plan([cls('a', '46'), cls('b', '34')], [46, 34])
check('two strict: queues 7 and 6, in the places\' order, mode 2', (queues(p), p['mode']),
      ({46: (7, 'strict', None), 34: (6, 'strict', None)}, 2))
p = plan([cls('a', '46', '300'), cls('b', '34', '200')], [34, 46])
check('the queues in the places\' order, as the rules hook gave them', queues(p),
      {34: (7, 'strict', None), 46: (6, 'strict', None)})

# ---- minimums ----
p = plan([cls('a', '46', minimum='30')], [46])
check('one class with a minimum: weighted, all weighted (mode 0), 30 turns against 70 for queue 0',
      (queues(p), p['mode'], counts(p['weights'])),
      ({46: (7, 'weighted', 30)}, 0, {7: 30, 6: 1, 5: 1, 4: 1, 3: 1, 2: 1, 1: 1, 0: 70}))
p = plan([cls('a', '46', minimum='20'), cls('b', '34', minimum='30')], [46, 34])
check('two minimums: queues 7 and 6 weighted, mode 0; 20, 30 and the rest, 50',
      (queues(p), p['mode'], counts(p['weights'])),
      ({46: (7, 'weighted', 20), 34: (6, 'weighted', 30)}, 0, {7: 20, 6: 30, 5: 1, 4: 1, 3: 1, 2: 1, 1: 1, 0: 50}))
p = plan([cls('a', '46', minimum='20'), cls('b', '46', minimum='15')], [46])
check('two classes of one DSCP: one queue, their minimums added',
      (queues(p), p['dscps'][0]['classes']), ({46: (7, 'weighted', 35)}, ['a', 'b']))
p = plan([cls('a', '46'), cls('b', '34', minimum='30')], [46, 34])
check('a minimum beside a strict class: refused - nothing for the switch', (p['refused'], p['mode'], p['weights']),
      ('mix', None, None))
p = plan([cls('a', '46', minimum='20'), cls('b', '46')], [46])
check('a minimum beside a strict class of the same DSCP: refused too', p['refused'], 'mix')
p = plan([cls('a', '46', minimum='60'), cls('b', '34', minimum='50')], [46, 34])
check('minimums past 100: refused - nothing for the switch', (p['refused'], p['mode'], p['weights']), ('over', None, None))
p = plan([cls('a', '46'), cls('b', '34'), cls('c', '40', minimum='20')], [46, 34])
check('a minimum on a third DSCP: not held - no queue of its own; no mix, it has no place',
      (p['classes']['c']['why'], p['classes']['c']['minimum_why'], p['refused']), ('third', 'not-hardware', ''))
p = plan([cls('a', '0', minimum='20'), cls('b', '46', minimum='10', ipprotocol='inet6')], [])
check('a minimum on Best Effort or IPv6 alone: not held', [p['classes'][u]['minimum_why'] for u in 'ab'],
      ['not-hardware', 'not-hardware'])
p = plan([cls('a', '46', minimum='20', enabled='0'), cls('b', '34')], [34])
check('a class switched off: no place, and its minimum nothing', (queues(p), p['classes']['a']['minimum_why']),
      ({34: (7, 'strict', None)}, ''))
for bad in ('0', '101', 'x', '-5', '1000'):
    check('a minimum of %r is none' % bad, plan([cls('a', '46', minimum=bad)], [46])['dscps'][0]['kind'], 'strict')
p = plan([cls('a', '46', minimum='100')], [46])
check('a minimum of 100: queue 0 still one turn, as every queue',
      counts(p['weights']), {7: 100, 6: 1, 5: 1, 4: 1, 3: 1, 2: 1, 1: 1, 0: 1})
p = plan([], [])
check('no class: nothing for the switch', (p['dscps'], p['mode'], p['weights']), ([], None, None))

# ---- Firewall: Shaper's parts ----
p = plan([cls('a', '46'), cls('b', '34')], [46, 34], {46: 70, 34: 20})
check('a part for every place, no minimum: weighted from Firewall: Shaper',
      (queues(p), p['dscps'][0]['from'], p['mode'], p['shares_why']),
      ({46: (7, 'weighted', 70), 34: (6, 'weighted', 20)}, 'shaper', 0, ''))
p = plan([cls('a', '46'), cls('b', '34')], [46, 34], {46: 70})
check('a part for one place of two: not kept - the other would be strict and go first',
      (queues(p)[46], p['shares_why']), ((7, 'strict', None), 'beside-strict'))
p = plan([cls('a', '46'), cls('b', '34')], [46, 34], {46: 70, 34: 50})
check('parts past 100: not kept', (queues(p)[46], p['shares_why']), ((7, 'strict', None), 'share-over'))
p = plan([cls('a', '46', minimum='20')], [46], {46: 70})
check('a class\'s own minimum before a part from Firewall: Shaper', (queues(p), p['dscps'][0]['from'], p['shares_why']),
      ({46: (7, 'weighted', 20)}, 'minimum', 'minimum-wins'))
p = plan([cls('a', '46')], [46], {34: 50})
check('a part for a DSCP with no place: nothing', (queues(p), p['shares_why']), ({46: (7, 'strict', None)}, 'beside-strict'))

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
