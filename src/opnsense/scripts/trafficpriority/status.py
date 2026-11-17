#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""
What the page shows, as one JSON object: whether Traffic Priority is on and, for each class, what pf was
given for it at the last filter reload (/tmp/rules.debug) and what pf holds now (pfctl -v -s rules) -
its rules, found by their label, and what pf counted for them since that reload; whether pf refused
the rule set of that reload; how many connections pf holds now with the mark of a class, each once
(pfctl -v -s states); and whether os-xgs-npu is installed, whose drivers carry a connection's mark
into hardware.

    status.py

Read only.
"""

import json
import os
import re
import subprocess
import xml.etree.ElementTree as ET

CONFIG = '/conf/config.xml'
PFCTL = '/sbin/pfctl'
RULES = '/tmp/rules.debug'          # the rules the last filter reload gave pf (OPNsense's filter.inc)
ERRORS = '/tmp/rules.error'         # why pf refused them, when it did (filter.inc:399-437)
LABEL = 'trafficpriority-'          # Marking::LABEL, followed by the class's UUID
LABELED = re.compile(r'label "' + LABEL + r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"')
# The counters pfctl -v prints under each rule (pfctl.c:1141-1161 in FreeBSD 15.1): packets and bytes
# both ways, the states made with the rule among their match rules that are open now (States), and
# all it made since the rule was loaded (State Creations) - for a match rule pf counts the states it
# matched (pf.c's STATE_INC_COUNTERS). A filter reload loads new rules, whose counters start at 0:
# only evaluations, packets and bytes are carried over, with keepcounters only (pf_ioctl.c:1553-1574).
COUNTERS = re.compile(r'^\s+\[ Evaluations: (\d+)\s+Packets: (\d+)\s+Bytes: (\d+)\s+States: (\d+)\s*\]')
CREATED = re.compile(r'^\s+\[ Inserted: .*State Creations: (\d+)\s*\]')
# pfctl -v -s states prints a line for each state - its interface, protocol and addresses, "<-" for
# one made coming in, "->" going out - and one beneath it with what pf does to its packets, the mark
# among them (pf_print_state.c:226-280, 342-383 in FreeBSD 15.1). pf keeps no note of which rules a
# state matched (pf_nl.c:148-230, its state export), only what they set on it.
SET_TOS = re.compile(r', set-tos (0x[0-9a-f]{2})\b')
# os-xgs-npu's model: where it is installed, its drivers give a connection in hardware its pf mark
PROJECT = '/usr/local/opnsense/mvc/app/models/OPNsense/XGS/XGS.xml'


def settings(path=None):
    """(on, [each class's uuid, whether it is switched on, its description and its DSCP]); None when
    config.xml cannot be read."""
    try:
        root = ET.parse(path or CONFIG).getroot()
    except (OSError, ET.ParseError):
        return None
    own = root.find('OPNsense/TrafficPriority')
    if own is None:
        return False, []
    on = (own.findtext('general/enabled') or '0') == '1'
    classes = []
    for node in own.findall('classes/class'):
        classes.append({
            'uuid': (node.get('uuid') or '').lower(),
            'enabled': (node.findtext('enabled') or '1') == '1',
            'description': node.findtext('description') or '',
            'dscp': (node.findtext('dscp') or '').strip(),
        })
    return on, classes


def tos(dscp):
    """The TOS byte pf sets for a DSCP, as pfctl prints it (Marking::tos()); None for anything that is
    not one of 0 to 63."""
    if not re.fullmatch(r'[0-9]{1,2}', dscp or '') or int(dscp) > 63:
        return None
    return '0x%02x' % (int(dscp) << 2)


def written(path=None):
    """Each class's rules in the file the last filter reload loaded, by label: those written, and those
    OPNsense wrote commented out because it could not place them - an interface that is not there, an
    address or a port it could not map."""
    out = {}
    try:
        with open(path or RULES, encoding='utf-8', errors='replace') as handle:
            for line in handle:
                found = LABELED.search(line)
                if not found:
                    continue
                entry = out.setdefault(found.group(1), {'written': 0, 'not_placed': 0})
                entry['not_placed' if line.lstrip().startswith('#') else 'written'] += 1
    except OSError:
        return None
    return out


def loaded(text):
    """Each class's rules in pf now, by label, from pfctl -v -s rules: how many, and their counters
    added up."""
    out = {}
    current = None
    for line in (text or '').splitlines():
        if not line[:1].isspace():
            found = LABELED.search(line)
            current = None
            if found:
                current = out.setdefault(found.group(1), {'rules': 0, 'packets': 0, 'bytes': 0, 'states': 0,
                                                          'created': 0})
                current['rules'] += 1
            continue
        if current is None:
            continue
        found = COUNTERS.match(line)
        if found:
            current['packets'] += int(found.group(2))
            current['bytes'] += int(found.group(3))
            current['states'] += int(found.group(4))
            continue
        found = CREATED.match(line)
        if found:
            current['created'] += int(found.group(1))
    return out


def marked(text, marks):
    """How many connections pf holds now with one of the marks given, each once, from pfctl -v -s
    states: the states made coming in that set one of those TOS bytes. A class's rules mark the state
    a connection makes where it comes in (match in); the state it makes going out carries no mark of
    theirs, so a connection is counted once, however many classes matched it, and whenever it opened -
    a filter reload leaves states and their marks as they are. A normalization rule of the owner's that
    sets one of the same marks on connections coming in is counted too: pf does not say which rule
    set it. None when pf could not be asked."""
    if text is None:
        return None
    count = 0
    inbound = False
    for line in text.splitlines():
        if not line[:1].isspace():
            inbound = ' <- ' in line
            continue
        found = SET_TOS.findall(line)
        if inbound and found and found[-1] in marks:
            count += 1
            inbound = False
    return count


def refused(rules=None, errors=None):
    """Whether pf refused the rule set the last filter reload wrote. OPNsense then loads the one before
    it again and writes why into /tmp/rules.error, after it wrote /tmp/rules.debug (filter.inc:399-437).
    That file stays until the firewall's status message is dismissed (FirewallStatus.php), so it counts
    only when it is not older than the rules file."""
    try:
        return os.stat(errors or ERRORS).st_mtime_ns >= os.stat(rules or RULES).st_mtime_ns
    except OSError:
        return False


def pf_show(what):
    """pfctl -v -s <what>, or None when pf could not be asked."""
    try:
        done = subprocess.run([PFCTL, '-v', '-s', what], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def status(config=None, rules=None, pf_text=None, project=None, states=None, errors=None):
    read = settings(config)
    if read is None:
        return {'error': 'config.xml could not be read'}
    on, classes = read
    lines = written(rules)
    held = loaded(pf_text)
    for entry in classes:
        entry.update({'written': 0, 'not_placed': 0, 'rules': 0, 'packets': 0, 'bytes': 0, 'states': 0,
                      'created': 0})
        entry.update((lines or {}).get(entry['uuid'], {}))
        entry.update(held.get(entry['uuid'], {}))
    # the marks of the classes pf holds rules for, each once
    marks = {tos(entry['dscp']) for entry in classes if entry['rules']} - {None}
    return {
        'enabled': on,
        'classes': classes,
        'rules_file': lines is not None,
        'pf': pf_text is not None,
        'refused': refused(rules, errors),
        'marked': marked(states, marks),
        'project': os.path.exists(project or PROJECT),
    }


def main():
    print(json.dumps(status(pf_text=pf_show('rules'), states=pf_show('states'))))


if __name__ == '__main__':
    main()
