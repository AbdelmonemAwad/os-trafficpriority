#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""status.py against the files it reads, written here as OPNsense and pfctl write them: config.xml's
classes, the rules the last filter reload loaded (/tmp/rules.debug, its lines as test-rules.php has
OPNsense's FilterRule write them), pf's rules with their counters (pfctl -v -s rules, as FreeBSD
15.1's pfctl.c and pfctl_parser.c print them), pf's states (pfctl -v -s states, as its
pf_print_state.c prints them) and /tmp/rules.error. Each class is found by its label alone, a rule
written commented out is not one placed, and another rule's counters are never added to a class's;
a connection is counted as marked once, coming in, with the mark of a class pf holds rules for; and
a rule set pf refused is told from one it took by the two files' times.

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

# pfctl -v -s states, as pf_print_state.c prints each state: a call to the firewall marked EF coming in
# on the LAN, and its way out over the WAN, which an owner's normalization rule marked going out; a
# connection with Video's mark (Video has no rule in pf), one with Bulk's (Bulk is off), one with no
# mark, and a DNS query marked EF coming in, more options after the mark
STATES = """all udp 192.168.1.1:5060 <- 192.168.1.20:5060       MULTIPLE:MULTIPLE
   age 00:01:12, expires in 00:01:00, 120:118 pkts, 24000:23600 bytes, rule 105, set-tos 0xb8
all udp 198.51.100.7:5060 (192.168.1.20:5060) -> 203.0.113.9:5060       MULTIPLE:MULTIPLE
   age 00:01:12, expires in 00:01:00, 120:118 pkts, 24000:23600 bytes, rule 98, set-tos 0xb8
all tcp 192.168.1.1:443 <- 192.168.1.30:51000       ESTABLISHED:ESTABLISHED
   age 00:10:00, expires in 23:59:59, 500:400 pkts, 50000:400000 bytes, rule 110, rlabel 02f4bab031b57d1e30553ce08e0ec131, set-tos 0x88
all tcp 203.0.113.9:443 <- 192.168.1.31:51001       ESTABLISHED:ESTABLISHED
   age 00:10:00, expires in 23:59:59, 5:4 pkts, 500:400 bytes, rule 110, set-tos 0x20
all icmp 192.168.1.1:3 <- 192.168.1.40:3       0:0
   age 00:00:05, expires in 00:00:05, 1:1 pkts, 84:84 bytes, rule 110
igb1 udp 192.168.1.1:53 <- 192.168.1.41:5353       SINGLE:MULTIPLE
   age 00:00:05, expires in 00:00:25, 1:1 pkts, 70:120 bytes, rule 110, allow-opts, set-tos 0xb8, max-mss 1400
"""

check('os-xgs-npu is looked for where it installs its model', status.PROJECT,
      '/usr/local/opnsense/mvc/app/models/OPNsense/XGS/XGS.xml')
check('the marks as pf prints them', [status.tos(d) for d in ('46', '0', '8', '63', '64', 'ef', '')],
      ['0xb8', '0x00', '0x20', '0xfc', None, None, None])

with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    rules = os.path.join(tmp, 'rules.debug')
    errors = os.path.join(tmp, 'rules.error')
    project = os.path.join(tmp, 'XGS.xml')
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write(CONFIG)
    with open(rules, 'w', encoding='utf-8') as handle:
        handle.write(RULES)

    on, classes = status.settings(config)
    check('the settings: on', on, True)
    check('the classes, in order, their UUIDs as the labels carry them (lower case)',
          [(c['uuid'], c['enabled'], c['description'], c['dscp']) for c in classes],
          [(U1, True, 'Voice', '46'), (U2, False, 'Bulk', '8'), (U3, True, 'Video', '34')])

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

    check('pf states: marked coming in with EF, each connection once', status.marked(STATES, {'0xb8'}), 2)
    check('pf states: with EF or AF41', status.marked(STATES, {'0xb8', '0x88'}), 3)
    check('pf states: none with a mark of no class', status.marked(STATES, set()), 0)
    check('pf states: nothing when pf could not be asked', status.marked(None, {'0xb8'}), None)

    got = status.status(config, rules, PF, project, STATES, errors)
    rows = {c['uuid']: c for c in got['classes']}
    check('status: on, the file read, pf asked and its rule set taken, no os-xgs-npu',
          (got['enabled'], got['rules_file'], got['pf'], got['refused'], got['project']), (True, True, True, False, False))
    check('status: Voice in pf, 4 connections matched now, 19 since loaded',
          {k: rows[U1][k] for k in ('written', 'not_placed', 'rules', 'states', 'created')},
          {'written': 2, 'not_placed': 0, 'rules': 2, 'states': 4, 'created': 19})
    check('status: Bulk, switched off, nothing anywhere',
          {k: rows[U2][k] for k in ('enabled', 'written', 'rules', 'states')},
          {'enabled': False, 'written': 0, 'rules': 0, 'states': 0})
    check('status: Video not placed, not in pf', (rows[U3]['not_placed'], rows[U3]['rules']), (1, 0))
    check('status: marked now, each once, with the mark of a class pf holds rules for (Voice\'s, not '
          'Video\'s or Bulk\'s) - not the 4 its rules count', got['marked'], 2)
    check('status: pf not asked for its states: no count', status.status(config, rules, PF, project, None, errors)['marked'],
          None)

    # pf refused the rule set: OPNsense writes rules.error after rules.debug, and it stays there until
    # it is dismissed, so one older than the rules file is a reload before the last one
    with open(errors, 'w', encoding='utf-8') as handle:
        handle.write('There were error(s) loading the rules: /tmp/rules.debug:19: syntax error')
    second = 1000000000
    os.utime(rules, ns=(1800000000 * second, 1800000000 * second))
    os.utime(errors, ns=(1800000000 * second + 1, 1800000000 * second + 1))
    check('rules.error written after rules.debug: refused', status.refused(rules, errors), True)
    os.utime(errors, ns=(1800000000 * second, 1800000000 * second))
    check('rules.error written in the same instant: refused', status.refused(rules, errors), True)
    os.utime(errors, ns=(1799999999 * second, 1799999999 * second))
    check('rules.error from an earlier reload: not refused', status.refused(rules, errors), False)
    check('status: an earlier refusal not said', status.status(config, rules, PF, project, STATES, errors)['refused'],
          False)
    os.utime(errors, ns=(1800000001 * second, 1800000001 * second))
    check('status: refused said', status.status(config, rules, PF, project, STATES, errors)['refused'], True)
    check('no rules.error: not refused', status.refused(rules, os.path.join(tmp, 'none')), False)
    check('no rules.debug: not refused', status.refused(os.path.join(tmp, 'none'), errors), False)

    with open(project, 'w', encoding='utf-8') as handle:
        handle.write('<model/>')
    check('status: os-xgs-npu installed', status.status(config, rules, PF, project, None, errors)['project'], True)
    gone = status.status(config, os.path.join(tmp, 'none'), None, project, None, errors)
    check('status: no rules file, pf not asked: said, and every class at nothing',
          (gone['rules_file'], gone['pf'], gone['marked'], sum(c['rules'] + c['written'] for c in gone['classes'])),
          (False, False, None, 0))

    with open(config, 'w', encoding='utf-8') as handle:
        handle.write('<opnsense><OPNsense><TrafficPriority><classes><class uuid="%s"><description>Unflagged</description>'
                     '<dscp>46</dscp></class></classes></TrafficPriority></OPNsense></opnsense>' % U1)
    check('a class with no enabled element: on, the model\'s default',
          [(c['enabled'], c['description']) for c in status.settings(config)[1]], [(True, 'Unflagged')])
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write('<opnsense><OPNsense/></opnsense>')
    check('status: never set: off, no class', (status.status(config, rules, PF, project, None, errors)['enabled'],
                                               status.status(config, rules, PF, project, None, errors)['classes']),
          (False, []))
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write('<opnsense>')
    check('status: config.xml unreadable: said', status.status(config, rules, PF, project, None, errors),
          {'error': 'config.xml could not be read'})

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
