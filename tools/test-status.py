#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""status.py against the files it reads, written here as OPNsense and pfctl write them: config.xml's
classes, the rules the last filter reload loaded (/tmp/rules.debug, its lines as test-rules.php has
OPNsense's FilterRule write them) and pf's rules with their counters (pfctl -v -s rules, as FreeBSD
15.1's pfctl.c and pfctl_parser.c print them). Each class is found by its label alone, a rule written
commented out is not one placed, and another rule's counters are never added to a class's.

    python3 tools/test-status.py"""
import importlib.util
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location(
    'status', os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'trafficpriority', 'status.py'))
status = importlib.util.module_from_spec(spec)
spec.loader.exec_module(status)

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


U1 = '6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a01'
U2 = '6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a02'
U3 = '6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a03'

CONFIG = """<?xml version="1.0"?>
<opnsense>
  <OPNsense>
    <TrafficPriority version="1.0.0">
      <general><enabled>1</enabled></general>
      <classes>
        <class uuid="%s"><enabled>1</enabled><description>Voice</description><dscp>46</dscp></class>
        <class uuid="%s"><enabled>0</enabled><description>Bulk</description><dscp>8</dscp></class>
        <class uuid="%s"><enabled>1</enabled><description>Video</description><dscp>34</dscp></class>
      </classes>
    </TrafficPriority>
  </OPNsense>
</opnsense>
""" % (U1, U2.upper(), U3)

# /tmp/rules.debug as OPNsense writes it: Voice on two interfaces, Video's rule commented out (its
# interface not there), and rules of OPNsense's own around them
RULES = """# [prio: 0]
match in on igb1 inet proto udp from {any} to {any} port {5060} scrub ( set-tos 0xb8 ) label "trafficpriority-%(u1)s" # Traffic Priority: Voice
match in on igb2 inet proto udp from {any} to {any} port {5060} scrub ( set-tos 0xb8 ) label "trafficpriority-%(u1)s" # Traffic Priority: Voice
#debug:Interface opt9 not found
# match in on ##opt9## inet from {any} to {any} scrub ( set-tos 0x88 ) label "trafficpriority-%(u3)s" # Traffic Priority: Video
# [prio: 1]
block in log inet from {any} to {any} label "02f4bab031b57d1e30553ce08e0ec131" # Default deny / state violation rule
""" % {'u1': U1, 'u3': U3}

# pfctl -v -s rules: the two Voice rules, and OPNsense's own after them, whose counters are not Voice's
PF = """match in on igb1 inet proto udp from any to any port = sip set ( tos 0xb8 ) label "trafficpriority-%(u1)s"
  [ Evaluations: 1520      Packets: 48210     Bytes: 9912345     States: 3     ]
  [ Source Nodes: 0      Limit: 0      NAT/RDR: 0      Route: 0      ]
  [ Inserted: uid 0 pid 51234 State Creations: 17    ]
match in on igb2 inet proto udp from any to any port = sip set ( tos 0xb8 ) label "trafficpriority-%(u1)s"
  [ Evaluations: 120       Packets: 210       Bytes: 12345      States: 1     ]
  [ Source Nodes: 0      Limit: 0      NAT/RDR: 0      Route: 0      ]
  [ Inserted: uid 0 pid 51234 State Creations: 2     ]
block drop in log inet all label "02f4bab031b57d1e30553ce08e0ec131"
  [ Evaluations: 99999     Packets: 77777     Bytes: 5555555    States: 0     ]
  [ Source Nodes: 0      Limit: 0      NAT/RDR: 0      Route: 0      ]
  [ Inserted: uid 0 pid 51234 State Creations: 0     ]
pass in quick on igb1 inet from 192.168.1.0/24 to any flags S/SA keep state label "trafficpriority-not-a-uuid"
  [ Evaluations: 5         Packets: 5         Bytes: 500        States: 5     ]
  [ Inserted: uid 0 pid 51234 State Creations: 5     ]
""" % {'u1': U1}

with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    rules = os.path.join(tmp, 'rules.debug')
    project = os.path.join(tmp, 'XGS.xml')
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write(CONFIG)
    with open(rules, 'w', encoding='utf-8') as handle:
        handle.write(RULES)

    on, classes = status.settings(config)
    check('the settings: on', on, True)
    check('the classes, in order, their UUIDs as the labels carry them (lower case)',
          [(c['uuid'], c['enabled'], c['description']) for c in classes],
          [(U1, True, 'Voice'), (U2, False, 'Bulk'), (U3, True, 'Video')])

    lines = status.written(rules)
    check('rules.debug: Voice written twice', lines.get(U1), {'written': 2, 'not_placed': 0})
    check('rules.debug: a rule written commented out is not placed', lines.get(U3), {'written': 0, 'not_placed': 1})
    check('rules.debug: no other rule taken for a class', sorted(lines), sorted([U1, U3]))

    held = status.loaded(PF)
    check('pf: Voice\'s two rules, their counters added up', held.get(U1),
          {'rules': 2, 'packets': 48420, 'bytes': 9924690, 'states': 4, 'created': 19})
    check('pf: the counters of a rule after a class\'s are not the class\'s', sorted(held), [U1])
    check('pf: nothing in an empty answer', status.loaded(''), {})
    check('pf: nothing when pf could not be asked', status.loaded(None), {})

    got = status.status(config, rules, PF, project)
    rows = {c['uuid']: c for c in got['classes']}
    check('status: on, the file read, pf asked, no os-xgs-npu',
          (got['enabled'], got['rules_file'], got['pf'], got['project']), (True, True, True, False))
    check('status: Voice in pf, 4 connections marked now, 19 since loaded',
          {k: rows[U1][k] for k in ('written', 'not_placed', 'rules', 'states', 'created')},
          {'written': 2, 'not_placed': 0, 'rules': 2, 'states': 4, 'created': 19})
    check('status: Bulk, switched off, nothing anywhere',
          {k: rows[U2][k] for k in ('enabled', 'written', 'rules', 'states')},
          {'enabled': False, 'written': 0, 'rules': 0, 'states': 0})
    check('status: Video not placed, not in pf', (rows[U3]['not_placed'], rows[U3]['rules']), (1, 0))

    with open(project, 'w', encoding='utf-8') as handle:
        handle.write('<model/>')
    check('status: os-xgs-npu installed', status.status(config, rules, PF, project)['project'], True)
    gone = status.status(config, os.path.join(tmp, 'none'), None, project)
    check('status: no rules file, pf not asked: said, and every class at nothing',
          (gone['rules_file'], gone['pf'], sum(c['rules'] + c['written'] for c in gone['classes'])), (False, False, 0))

    with open(config, 'w', encoding='utf-8') as handle:
        handle.write('<opnsense><OPNsense/></opnsense>')
    check('status: never set: off, no class', (status.status(config, rules, PF, project)['enabled'],
                                               status.status(config, rules, PF, project)['classes']), (False, []))
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write('<opnsense>')
    check('status: config.xml unreadable: said', status.status(config, rules, PF, project),
          {'error': 'config.xml could not be read'})

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
