#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""
Which classes go to the switch's queues on an XGS appliance, which queue each takes, how the queues are
scheduled and with what weights - from the classes in config.xml, their minimums, and the shares
shaper_map.py takes from Firewall: Shaper. Read only: apply.py writes what this decides into
os-xgs-npu's settings file for the switch (switch_qos.py), and status.py shows it.

WHAT THE SWITCH CAN DO, measured by os-xgs-npu on the second XGS 3300 (2026-11-11, 2026-11-17):
  - a frame the coprocessor sends into the switch waits in queue 0 whatever its DSCP, unless a TCAM
    entry on the switch's port 0 picks it out by its DSCP and sets its queue. Two entries are free,
    so two DSCPs at most go to a queue of their own; the classes marking any other DSCP are marked
    by pf and nothing more;
  - one entry serves every front port behind the switch at once: the queue is set where the frame
    enters the switch, and each front port then serves its queues as its scheduling says;
  - the scheduling is per port - strict for the top 1 to 6 queues and weighted for the rest, or all
    weighted, or all strict - and the weights are ONE sequence for the whole chip, so a minimum is one
    proportion for every port in weighted mode, the coprocessor's own uplink among them;
  - the key is IPv4's: an IPv6 class's frames stay in queue 0.

HOW THE CLASSES BECOME QUEUES. The classes switched on, in the order the page shows them (by
sequence, then as listed): each DSCP other than Best Effort (0), on a class that marks IPv4, takes the
next of the two hardware places until both are taken; classes marking a DSCP that has a place share
it. A DSCP whose classes have no minimum, and no share from Firewall: Shaper, is STRICT: it goes
first, before every other queue. One with a minimum, or a share, is WEIGHTED: under full load its
queue gets at least that part of a port, everything else (queue 0) the rest. Strict queues take the
top places, 7 then 6, the weighted ones the places below them; the ports' scheduling is the number of
strict queues (UMSD's mode 1 or 2), or 0 - all weighted - with none. A strict queue can take a whole
port: phase 0 measured a bulk stream marked EF taking 912 to 984 Mbit/s and leaving an unmarked one 0
to 31, and a weighted queue is what guarantees the rest a part.

THE WEIGHTS. A sequence of turns, each queue as many as its share in percent - queue 0 the part
left - and every queue at least one, so that no port ever shuts one out (os-xgs-npu refuses a
sequence that does). Whether the switch counts a turn in frames or in bytes is not in UMSD's source and
not measured: a class of small packets beside one of large ones may get less of the port's bits than
its share. Measured: UMSD's own default, 33, 25, 17, 12, 6, 3, 2, 1 for queues 7 to 0, read on the
XGS 3300; not yet a sequence written.
"""

import re
import xml.etree.ElementTree as ET

ENTRIES = 2                 # TCAM entries 3 and 255: the switch tool's two places
NO_SEQUENCE = 100000        # Marking::NO_SEQUENCE: a class whose sequence cannot be read goes first
MAX_TURNS = 128             # the chip's weight table


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


def places(classes):
    """The DSCPs that go to the switch, in order, at most two, and why each class does or does not:
    ([dscp, ...], {uuid: 'hardware' | 'third' | 'best-effort' | 'ipv6' | 'dscp' | 'off'})."""
    taken, why = [], {}
    for c in classes:
        if not switched_on(c):
            why[c['uuid']] = 'off'
    for c in ordered(classes):
        d = dscp(c.get('dscp'))
        if d is None:
            why[c['uuid']] = 'dscp'
        elif d == 0:
            why[c['uuid']] = 'best-effort'
        elif (c.get('ipprotocol') or 'inet') == 'inet6':
            why[c['uuid']] = 'ipv6'
        elif d in taken:
            why[c['uuid']] = 'hardware'
        elif len(taken) < ENTRIES:
            taken.append(d)
            why[c['uuid']] = 'hardware'
        else:
            why[c['uuid']] = 'third'
    return taken, why


def plan(classes, shares=None):
    """What the switch is given for the classes: {'dscps': [{'dscp', 'queue', 'kind' ('strict' or
    'weighted'), 'percent', 'from' ('minimum', 'shaper' or None), 'classes': [uuid, ...]}],
    'classes': {uuid: {'why', 'dscp', 'queue', 'kind', 'percent', 'minimum': the class's own or None,
    'minimum_why': '' | 'not-hardware' | 'over'}}, 'mode': 0-7 or None, 'weights': [...] or None,
    'percent': {queue: percent}}. shares: {dscp: percent} from Firewall: Shaper, for a DSCP whose
    classes give no minimum of their own."""
    shares = shares or {}
    taken, why = places(classes)
    rows = {c['uuid']: {'why': why.get(c['uuid'], 'off'), 'dscp': dscp(c.get('dscp')), 'queue': None,
                        'kind': None, 'percent': None, 'minimum': minimum_of(c.get('minimum')), 'minimum_why': ''}
            for c in classes}
    # the minimums, in the page's order, while they fit in a port
    total = 0
    percent = {d: 0 for d in taken}
    source = {d: None for d in taken}
    for c in ordered(classes):
        row = rows[c['uuid']]
        if row['minimum'] is None:
            continue
        if row['why'] != 'hardware':
            row['minimum_why'] = 'not-hardware'
            continue
        if total + row['minimum'] > 100:
            row['minimum_why'] = 'over'
            continue
        total += row['minimum']
        percent[row['dscp']] += row['minimum']
        source[row['dscp']] = 'minimum'
    # Firewall: Shaper's shares, for a DSCP without a minimum of its own, while they fit too
    for d in taken:
        if source[d] is None and d in shares and total + shares[d] <= 100:
            total += shares[d]
            percent[d] = shares[d]
            source[d] = 'shaper'
    strict = [d for d in taken if source[d] is None]
    weighted = [d for d in taken if source[d] is not None]
    queue = {}
    q = 7
    for d in strict + weighted:
        queue[d] = q
        q -= 1
    dscps = []
    for d in taken:
        dscps.append({'dscp': d, 'queue': queue[d], 'kind': 'strict' if source[d] is None else 'weighted',
                      'percent': percent[d] if source[d] else None, 'from': source[d],
                      'classes': [c['uuid'] for c in ordered(classes) if rows[c['uuid']]['why'] == 'hardware'
                                  and rows[c['uuid']]['dscp'] == d]})
    for c in classes:
        row = rows[c['uuid']]
        if row['why'] == 'hardware':
            row['queue'] = queue[row['dscp']]
            row['kind'] = 'strict' if source[row['dscp']] is None else 'weighted'
            row['percent'] = percent[row['dscp']] if source[row['dscp']] else None
    by_queue = {queue[d]: percent[d] for d in weighted}
    return {'dscps': dscps, 'classes': rows, 'mode': len(strict) if taken else None,
            'weights': turns(by_queue) if weighted else None, 'percent': by_queue}


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
