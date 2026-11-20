#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""
Which classes go to the switch's queues on an XGS appliance, which queue each takes, how the queues are
scheduled and with what weights - from the classes in config.xml, their minimums, the shares
shaper_map.py takes from Firewall: Shaper, and the places the last filter reload gave pf. Read only:
apply.py writes what this decides into os-xgs-npu's settings file for the switch (switch_qos.py), and
status.py shows it.

THE PLACES COME WITH THE RULES FILE. The rules hook decides at every filter reload whether a class
has a place in the switch (OPNsense\\TrafficPriority\\Hardware) - at most two DSCPs, those of the
classes switched on that make a rule, in the page's order, IPv4, above Best Effort - and while one has,
it writes before every class's rule the one that sets every IPv4 connection's DSCP to 0, both ways,
labelled "trafficpriority-clear": the switch queues every frame by its DSCP, whoever marked it, so only
the classes' connections may carry one. This reads the file (from_rules()): the switch is given the
classes' DSCPs only while the file holds that rule, and the places are taken as the hook takes them,
from the classes whose own rules the file holds (places_of()) - a class it holds no rule for has none.
But a class the reload left idle - no rule only because its groups and users, or its applications and
categories, had no table, nothing else wrong with it - keeps its place: the hook gives it one by its
settings, as the model does at the save, and writes a line for it into the same file, commented out, that
pf never reads (idle_in(), Marking::idleRecord()); its rules come back with the other plugin's tables - at
that plugin's Apply, whose filter reload writes them - with no Apply of this plugin's, the switch's entry
already there. Its queue holds nothing meanwhile. A class with something else wrong with it gets no such
line, and no place, here as there.

WHAT THE SWITCH CAN DO, measured by os-xgs-npu on the second XGS 3300 (2026-11-11, 2026-11-17):
  - a frame the coprocessor sends into the switch waits in queue 0 whatever its DSCP, unless a TCAM
    entry on the switch's port 0 picks it out by its DSCP and sets its queue;
  - one entry serves every front port behind the switch at once: the queue is set where the frame
    enters the switch, and each front port then serves its queues as its scheduling says;
  - the scheduling is per port - strict for the top 1 to 6 queues and weighted for the rest, or all
    weighted, or all strict - and the weights are ONE sequence for the whole chip, so a minimum is one
    proportion for every port in weighted mode, the coprocessor's own uplink among them;
  - the key is IPv4's: an IPv6 class's frames stay in queue 0.

STRICT, OR MINIMUMS - NOT BOTH. With no minimum, a place's DSCP is strict: it goes first, before every
other queue, top queues first (7, then 6), and can take a whole port - phase 0 measured a bulk stream
marked EF taking 912 to 984 Mbit/s and leaving an unmarked one 0 to 31. With minimums, the places'
queues are weighted: under full load each keeps at least its part of a port, and the rest of the
traffic (queue 0) keeps what is left. A strict queue beside a weighted one would go before it and leave
it no minimum, so the two are not mixed: every class with a place has a minimum, or none has - else
nothing is given to the switch, and Apply says why. The minimums add up to 100 at most. Firewall:
Shaper's parts make the places weighted only where no class has a minimum, every place has one, and
they fit in 100.

THE WEIGHTS. A sequence of turns, each queue as many as its share in percent - queue 0 the part
left - and every queue at least one, so that no port ever shuts one out (os-xgs-npu refuses a
sequence that does). Queues 1 to 6, which no place uses, get one turn each: the frames the clients
mark themselves with DSCP 8 to 55 wait in them on the switch's way into the coprocessor (port 0), each
queue its single turn in about a hundred when that link is full. Whether the switch counts a turn in
frames or in bytes is not in UMSD's source and not measured: a class of small packets beside one of
large ones may get less of the port's bits than its share. A sequence of 105 turns was written and
read back on the second XGS 3300 (2026-11-19), and its parts held only with port 0's pause off: 30
against 20 turns shared a full port 59 to 41 then, 98 to 2 with it on. os-xgs-npu's switch tool turns
the pause off whenever it writes a sequence, and puts it back when the sequence goes.
"""

import re
import xml.etree.ElementTree as ET

ENTRIES = 2                 # TCAM entries 3 and 255: the switch tool's two places
NO_SEQUENCE = 100000        # Marking::NO_SEQUENCE: a class whose sequence cannot be read goes first
MAX_TURNS = 128             # the chip's weight table
BELOW = {0: 'best-effort', 1: 'below-default', 8: 'below-default'}     # Hardware::BELOW
CLEAR = re.compile(r'label "trafficpriority-clear"')       # Hardware::LABEL
LABELED = re.compile(r'label "trafficpriority-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"')
# Marking::IDLE_LABEL: the line recording a class the reload left idle
IDLED = re.compile(r'label "trafficpriority-idle-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"')


def dscp(value):
    """A DSCP as the model stores it, 0 to 63; None for anything else (Marking::dscp())."""
    value = (value or '').strip()
    if not re.fullmatch(r'[0-9]{1,2}', value) or int(value) > 63:
        return None
    return int(value)


def sequence_of(value):
    """Marking::sequence(): a class whose sequence cannot be read goes first."""
    value = (value or '').strip()
    return int(value) if re.fullmatch(r'[0-9]+', value) else NO_SEQUENCE


def minimum_of(value):
    """A minimum as the model stores it, 1 to 100 percent; None when there is none or it is not one
    (Hardware::minimum())."""
    value = (value or '').strip()
    if not re.fullmatch(r'[0-9]{1,3}', value) or not 1 <= int(value) <= 100:
        return None
    return int(value)


def switched_on(c):
    """As the rules hook reads it: on unless it says otherwise ('' is not on)."""
    return c.get('enabled', '1') == '1'


def read_classes(root):
    """(on, follow Shaper, [each class as a dict of its fields, 'uuid' among them, in config.xml's
    order]) from config.xml's root element; (False, False, []) without the plugin's settings."""
    own = root.find('OPNsense/TrafficPriority') if root is not None else None
    if own is None:
        return False, False, []
    on = (own.findtext('general/enabled') or '0') == '1'
    follow = (own.findtext('general/follow_shaper') or '0') == '1'
    out = []
    for node in own.findall('classes/class'):
        fields = {child.tag: (child.text or '') for child in node}
        fields['uuid'] = (node.get('uuid') or '').lower()
        out.append(fields)
    return on, follow, out


def ordered(classes):
    """The classes switched on, as the page shows them: by sequence, then as listed."""
    on = [(i, c) for i, c in enumerate(classes) if switched_on(c)]
    on.sort(key=lambda ic: (sequence_of(ic[1].get('sequence')), ic[0]))
    return [c for _, c in on]


def from_rules(text):
    """What the last filter reload gave pf, from its rules file: (whether it holds the rule that sets
    every IPv4 connection's DSCP to 0, the UUIDs of the classes it wrote a rule for). A rule written
    commented out - OPNsense could not place it - counts for neither."""
    cleared, written = False, set()
    for line in (text or '').splitlines():
        if line.lstrip().startswith('#'):
            continue
        if CLEAR.search(line):
            cleared = True
        found = LABELED.search(line)
        if found:
            written.add(found.group(1))
    return cleared, written


def idle_in(text):
    """The classes the last filter reload left idle, as it recorded them in its rules file: for each, a line
    OPNsense wrote commented out - a rule the hook registered disabled - labelled
    "trafficpriority-idle-<its UUID>" (Marking::idleRecord()). The hook writes one only for a class with
    nothing wrong with it but tables missing on one side; only such a line, commented, counts."""
    out = set()
    for line in (text or '').splitlines():
        if not line.lstrip().startswith('#'):
            continue
        found = IDLED.search(line)
        if found:
            out.add(found.group(1))
    return out


def places_of(classes, written, cleared, idle=()):
    """The DSCPs with a queue of their own, in order, as the rules hook takes them (Hardware::places()):
    those of the classes switched on whose rules the file holds (written) - or that the reload left idle,
    recorded in the same file (idle_in()) - in the page's order, IPv4, above Best Effort, two at most. None
    while the file does not hold the rule that sets every IPv4 connection's DSCP to 0 (cleared): the
    switch then holds no class's queue."""
    out = []
    if not cleared:
        return out
    for c in ordered(classes):
        d = dscp(c.get('dscp'))
        if (c['uuid'] not in written and c['uuid'] not in idle) or d is None or d in BELOW or \
                (c.get('ipprotocol') or 'inet') == 'inet6':
            continue
        if d not in out and len(out) < ENTRIES:
            out.append(d)
    return out


def plan(classes, places, written, shares=None, idle=()):
    """What the switch is given for the classes: {'dscps': [{'dscp', 'queue', 'kind' ('strict' or
    'weighted'), 'percent', 'from' ('minimum', 'shaper' or None), 'classes': [uuid, ...]}],
    'classes': {uuid: {'why', 'dscp', 'queue', 'kind', 'percent', 'minimum': the class's own or None,
    'minimum_why': '' | 'not-hardware', 'idle': True when the last filter reload left it idle}},
    'mode': 0-7 or None, 'weights': [...] or None, 'percent': {queue: percent}, 'refused': '' | 'mix' |
    'over', 'shares_why': '' | 'minimum-wins' | 'beside-strict' | 'share-over'}. places: places_of();
    written: from_rules(); idle: the classes the last filter reload left idle (idle_in()), which keep their
    place. shares: {dscp: percent} from Firewall: Shaper. With 'refused', nothing is for the switch."""
    shares = shares or {}
    rows = {}
    for c in classes:
        d = dscp(c.get('dscp'))
        if not switched_on(c):
            why = 'off'
        elif c['uuid'] not in written and c['uuid'] not in idle:
            why = 'rule'
        elif d is None:
            why = 'dscp'
        elif d in BELOW:
            why = BELOW[d]
        elif (c.get('ipprotocol') or 'inet') == 'inet6':
            why = 'ipv6'
        elif d in places:
            why = 'hardware'
        else:
            why = 'third' if len(places) >= ENTRIES else 'no-place'
        minimum = minimum_of(c.get('minimum'))
        rows[c['uuid']] = {'why': why, 'dscp': d, 'queue': None, 'kind': None, 'percent': None,
                           'minimum': minimum,
                           'minimum_why': 'not-hardware' if minimum is not None and why not in ('hardware', 'off') else '',
                           'idle': switched_on(c) and c['uuid'] in idle and c['uuid'] not in written}
    held = [c for c in ordered(classes) if rows[c['uuid']]['why'] == 'hardware']
    taken = [d for d in places if any(rows[c['uuid']]['dscp'] == d for c in held)]
    out = {'dscps': [], 'classes': rows, 'mode': None, 'weights': None, 'percent': {}, 'refused': '',
           'shares_why': ''}
    with_minimum = [c for c in held if rows[c['uuid']]['minimum'] is not None]
    if with_minimum and len(with_minimum) < len(held):
        out['refused'] = 'mix'
    elif sum(rows[c['uuid']]['minimum'] for c in with_minimum) > 100:
        out['refused'] = 'over'
    percent, source = {d: 0 for d in taken}, {d: None for d in taken}
    if not out['refused']:
        if with_minimum:
            for c in with_minimum:
                percent[rows[c['uuid']]['dscp']] += rows[c['uuid']]['minimum']
                source[rows[c['uuid']]['dscp']] = 'minimum'
            if shares:
                out['shares_why'] = 'minimum-wins'
        elif shares:
            mine = {d: shares[d] for d in taken if d in shares}
            if len(mine) < len(taken):
                out['shares_why'] = 'beside-strict'
            elif sum(mine.values()) > 100:
                out['shares_why'] = 'share-over'
            else:
                for d, p in mine.items():
                    percent[d], source[d] = p, 'shaper'
    weighted = bool(taken) and all(source[d] for d in taken)
    queue = {d: 7 - i for i, d in enumerate(taken)}
    for d in taken:
        out['dscps'].append({'dscp': d, 'queue': queue[d], 'kind': 'weighted' if weighted else 'strict',
                             'percent': percent[d] if weighted else None, 'from': source[d] if weighted else None,
                             'classes': [c['uuid'] for c in held if rows[c['uuid']]['dscp'] == d]})
    for c in held:
        row = rows[c['uuid']]
        row['queue'] = queue[row['dscp']]
        row['kind'] = 'weighted' if weighted else 'strict'
        row['percent'] = percent[row['dscp']] if weighted else None
    if taken and not out['refused']:
        out['mode'] = 0 if weighted else len(taken)
        if weighted:
            out['percent'] = {queue[d]: percent[d] for d in taken}
            out['weights'] = turns(out['percent'])
    return out


def turns(percent):
    """The chip's weight sequence for {queue: percent}: each queue as many turns as its percent, queue
    0 the part left, every queue at least one, spread out (a smooth weighted round robin: each turn
    goes to the queue furthest behind its share, the higher queue first of two)."""
    count = dict.fromkeys(range(8), 0)
    for q, p in percent.items():
        count[q] += p
    count[0] += max(0, 100 - sum(percent.values()))
    for q in count:
        count[q] = max(1, count[q])
    total = sum(count.values())
    if total > MAX_TURNS:
        raise ValueError('more turns than the chip holds: %d' % total)
    current = dict.fromkeys(count, 0)
    out = []
    for _ in range(total):
        for q in count:
            current[q] += count[q]
        best = max(count, key=lambda k: (current[k], k))
        current[best] -= total
        out.append(best)
    return out


def config(path):
    """config.xml's root element, or None."""
    try:
        return ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return None
