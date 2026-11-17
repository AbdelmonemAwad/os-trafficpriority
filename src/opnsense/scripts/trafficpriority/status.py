#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""
What the page shows, as one JSON object: whether Traffic Priority is on and, for each class, what pf was
given for it at the last filter reload (/tmp/rules.debug) and what pf holds now (pfctl -v -s rules) -
its rules, found by their label, and the connections they marked; and whether os-xgs-npu is installed,
whose drivers carry a connection's mark into hardware.

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
LABEL = 'trafficpriority-'          # Marking::LABEL, followed by the class's UUID
LABELED = re.compile(r'label "' + LABEL + r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"')
# The counters pfctl -v prints under each rule (pfctl.c:1141-1161 in FreeBSD 15.1): packets and bytes
# both ways, the states made with the rule among their match rules that are open now (States), and
# all it made since the rule was loaded (State Creations) - for a match rule pf counts the states it
# matched (pf.c's STATE_INC_COUNTERS).
COUNTERS = re.compile(r'^\s+\[ Evaluations: (\d+)\s+Packets: (\d+)\s+Bytes: (\d+)\s+States: (\d+)\s*\]')
CREATED = re.compile(r'^\s+\[ Inserted: .*State Creations: (\d+)\s*\]')
# os-xgs-npu's model: where it is installed, its drivers give a connection in hardware its pf mark
PROJECT = '/usr/local/opnsense/mvc/app/models/OPNsense/XGS/XGS.xml'


def settings(path=None):
    """(on, [each class's uuid, whether it is switched on, and its description]); None when config.xml
    cannot be read."""
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
        })
    return on, classes


def written(path=None):
    """Each class's rules in the file the last filter reload loaded, by label: those written, and those
    OPNsense wrote commented out because it could not place them - an interface that is not there, an
    address it could not read."""
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


def pf_rules():
    """pfctl -v -s rules, or None when pf could not be asked."""
    try:
        done = subprocess.run([PFCTL, '-v', '-s', 'rules'], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def status(config=None, rules=None, pf_text=None, project=None):
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
    return {
        'enabled': on,
        'classes': classes,
        'rules_file': lines is not None,
        'pf': pf_text is not None,
        'project': os.path.exists(project or PROJECT),
    }


def main():
    print(json.dumps(status(pf_text=pf_rules())))


if __name__ == '__main__':
    main()
