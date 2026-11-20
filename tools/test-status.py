#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""status.py against the files it reads, written here as OPNsense and pfctl write them: config.xml's
classes, the rules the last filter reload loaded (/tmp/rules.debug, its lines as test-rules.php has
OPNsense's FilterRule write them), pf's rules with their counters (pfctl -v -s rules, as FreeBSD
15.1's pfctl.c and pfctl_parser.c print them), pf's states (pfctl -v -s states, as its
pf_print_state.c prints them - every mark as 0x00, the value not being in the state export pfctl
reads, as an XGS 3300 on 26.7.9 showed) and /tmp/rules.error. Each class is found by its label alone,
a rule written commented out is not one placed, and another rule's counters are never added to a
class's; a connection pf marked coming in is counted once, when a class pf holds rules for marks; and
a rule set pf refused is told from one it took by the two files' times. And each class's groups and
users, applications and categories with their tables, or why they have none, what pf holds in each table
now - each asked once, none for a class switched off - and whether the two plugins are installed.

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

# pfctl -v -s states as FreeBSD 15.1's pfctl prints them: a marked state as ", set-tos 0x00", whatever
# its mark - pfctl reads the states over netlink, whose export carries the flag and not the value (an
# XGS 3300 on 26.7.9, 2026-11-17: a class's EF on the wire, 0xb8, and "set-tos 0x00" on its three
# states). A call to the firewall marked coming in on the LAN, and its way out over the WAN, marked
# going out by an owner's normalization rule; two connections coming in with no mark; and a DNS query
# marked coming in, more options after the mark.
STATES = """all udp 192.168.1.1:5060 <- 192.168.1.20:5060       MULTIPLE:MULTIPLE
   age 00:01:12, expires in 00:01:00, 120:118 pkts, 24000:23600 bytes, rule 105, set-tos 0x00
all udp 198.51.100.7:5060 (192.168.1.20:5060) -> 203.0.113.9:5060       MULTIPLE:MULTIPLE
   age 00:01:12, expires in 00:01:00, 120:118 pkts, 24000:23600 bytes, rule 98, set-tos 0x00
all tcp 192.168.1.1:443 <- 192.168.1.30:51000       ESTABLISHED:ESTABLISHED
   age 00:10:00, expires in 23:59:59, 500:400 pkts, 50000:400000 bytes, rule 110, rlabel 02f4bab031b57d1e30553ce08e0ec131
all icmp 192.168.1.1:3 <- 192.168.1.40:3       0:0
   age 00:00:05, expires in 00:00:05, 1:1 pkts, 84:84 bytes, rule 110
igb1 udp 192.168.1.1:53 <- 192.168.1.41:5353       SINGLE:MULTIPLE
   age 00:00:05, expires in 00:00:25, 1:1 pkts, 70:120 bytes, rule 110, allow-opts, set-tos 0x00, max-mss 1400
"""
# one state each, as the lab's: coming in marked, coming in not marked, going out marked
IN_MARKED = """all udp 192.168.1.1:5321 <- 192.168.1.20:40000       MULTIPLE:MULTIPLE
   age 00:00:30, expires in 00:01:00, 3000:0 pkts, 4200000:0 bytes, rule 105, set-tos 0x00
"""
IN_PLAIN = """all udp 192.168.1.1:5321 <- 192.168.1.20:40000       MULTIPLE:MULTIPLE
   age 00:00:30, expires in 00:01:00, 3000:0 pkts, 4200000:0 bytes, rule 105
"""
OUT_MARKED = """all udp 198.51.100.7:5321 (192.168.1.20:40000) -> 203.0.113.9:5321       MULTIPLE:MULTIPLE
   age 00:00:30, expires in 00:01:00, 3000:0 pkts, 4200000:0 bytes, rule 98, set-tos 0x00
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

    check('pf states: a state coming in, shown with set-tos 0x00, counted', status.marked(IN_MARKED, {'0xb8'}), 1)
    check('pf states: a state coming in with no set-tos, not counted', status.marked(IN_PLAIN, {'0xb8'}), 0)
    check('pf states: a state going out with set-tos, not counted', status.marked(OUT_MARKED, {'0xb8'}), 0)
    check('pf states: each connection marked coming in counted once, whatever the class\'s mark',
          [status.marked(STATES, marks) for marks in ({'0xb8'}, {'0x88'}, {'0x00'}, {'0xb8', '0x20'})], [2, 2, 2, 2])
    check('pf states: no class marking, 0', (status.marked(STATES, set()), status.marked(IN_MARKED, set())), (0, 0))
    check('pf states: pf not asked, nothing', (status.marked(None, {'0xb8'}), status.marked(None, set())), (None, None))

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
    check('status: marked now, each connection pf marked coming in once - not the 4 Voice\'s rules count',
          got['marked'], 2)
    check('status: no class in pf, so none marking: 0, whatever pf marked',
          status.status(config, rules, '', project, STATES, errors)['marked'], 0)
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

    # the switch's queues: what Apply gives the switch, from the classes the rules file holds a rule for
    # while it holds the one setting every IPv4 connection's DSCP to 0; what the
    # last Apply did, shown whatever else is said; the switch read again, when asked
    xgs = {'assembly': 'AMDA0202-0004', 'family': 'octeontx', 'writes': True, 'why': '', 'devices': {}}
    placed = os.path.join(tmp, 'placed.debug')
    with open(placed, 'w', encoding='utf-8') as handle:
        handle.write('match in inet from {any} to {any} scrub ( set-tos 0x00 ) label "trafficpriority-clear"\n' + RULES)
    kept = os.path.join(tmp, 'hardware.json')
    hw = status.status(config, placed, PF, project, None, errors, model=xgs, result=kept)['hardware']
    check('status: the switch - Voice\'s EF placed by the rules file, queue 7 strict; no Apply yet, nothing pending',
          (hw['why_not'], [d['dscp'] for d in hw['dscps']], hw['classes'][U1]['queue'], hw['last'], hw['pending']),
          ('', [46], 7, None, True))
    with open(kept, 'w', encoding='utf-8') as handle:
        handle.write('{"status": "running", "said": "", "time": "2026-11-19 12:00:00 UTC"}')
    hw = status.status(config, placed, PF, project, None, errors, model=xgs, result=kept)['hardware']
    check('status: an Apply still running - said, and not pending', (hw['last']['status'], hw['pending']), ('running', False))
    with open(kept, 'w', encoding='utf-8') as handle:
        handle.write('{"status": "failed", "said": "not read back as written", "time": "x", "conf": null}')
    hw = status.status(config, rules, PF, project, None, errors, model=None, result=kept,
                       check={'ok': False, 'changed': ['entry:3']})['hardware']
    check('status: a put-back that failed shown even with no switch to set now; the switch read again passed on',
          (hw['why_not'], hw['last']['status'], hw['last']['said'], hw['check']['changed']),
          ('no-project', 'failed', 'not read back as written', ['entry:3']))

    with open(project, 'w', encoding='utf-8') as handle:
        handle.write('<model/>')
    check('status: os-xgs-npu installed', status.status(config, rules, PF, project, None, errors)['project'], True)
    gone = status.status(config, os.path.join(tmp, 'none'), None, project, None, errors)
    check('status: no rules file, pf not asked: said, and every class at nothing',
          (gone['rules_file'], gone['pf'], gone['marked'], sum(c['rules'] + c['written'] for c in gone['classes'])),
          (False, False, None, 0))

    # groups and users, applications and categories: each one's table or why it has none, what pf holds in each
    # table now - asked once a table, and not for a class switched off - and whether the two plugins are installed
    alice = '7a1c2e30-5b6d-4e8f-9a0b-1c2d3e4f5a02'
    gone = '7a1c2e30-5b6d-4e8f-9a0b-1c2d3e4f5a07'
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write(
            '<opnsense><OPNsense><TrafficPriority><general><enabled>1</enabled></general><classes>'
            '<class uuid="%s"><enabled>1</enabled><description>Calls</description><dscp>46</dscp><users>%s</users>'
            '<application>Zoom,Netflix</application><categories>VoIP</categories></class>'
            '<class uuid="%s"><enabled>1</enabled><description>Gone</description><dscp>34</dscp><users>%s</users></class>'
            '<class uuid="%s"><enabled>0</enabled><description>Off</description><dscp>40</dscp><users>%s</users>'
            '<application>Teams</application></class>'
            '</classes></TrafficPriority>'
            '<UserIdentity><general><enabled>1</enabled></general><users><user uuid="%s"><enabled>1</enabled>'
            '<name>alice</name><alias>uid_alice</alias></user></users></UserIdentity>'
            '<AppControl><general><classify>1</classify></general></AppControl>'
            '<Firewall><Alias><aliases>'
            '<alias><name>uid_alice</name><type>external</type><enabled>1</enabled><description>User Identity: user alice'
            '</description></alias>'
            '<alias><name>appcontrol_Zoom</name><type>external</type><enabled>1</enabled><description>Application Control: '
            'Zoom</description></alias>'
            '<alias><name>appcontrol_cat_VoIP</name><type>external</type><enabled>1</enabled><description>Application '
            'Control: category VoIP</description></alias>'
            '<alias><name>appcontrol_Teams</name><type>external</type><enabled>1</enabled><description>Application '
            'Control: Teams</description></alias>'
            '</aliases></Alias></Firewall></OPNsense></opnsense>' % (U1, alice, U2, gone, U3, alice, alice))
    asked = []

    def counts(table):
        asked.append(table)
        return {'uid_alice': 1, 'appcontrol_Zoom': 14}.get(table)

    got = status.status(config, rules, PF, project, None, errors, counts=counts,
                        installed={'identity': True, 'appcontrol': True})
    rows = {c['uuid']: c for c in got['classes']}
    check('status: each item of a class - its table and what pf holds in it, or why it has none',
          [(i['kind'], i['name'], i['table'], i['why'], i['count']) for i in rows[U1]['tables']],
          [('user', 'alice', 'uid_alice', '', 1), ('application', 'Zoom', 'appcontrol_Zoom', '', 14),
           ('application', 'Netflix', '', 'no-table', None), ('category', 'VoIP', 'appcontrol_cat_VoIP', '', None)])
    check('status: each table asked once, the table of a class switched off alone not asked, its count none',
          (sorted(asked), [(i['table'], i['count']) for i in rows[U3]['tables']]),
          (['appcontrol_Zoom', 'appcontrol_cat_VoIP', 'uid_alice'], [('uid_alice', None), ('appcontrol_Teams', None)]))
    check('status: a class with no table for its users now - idle, the users\' side; one with them, not',
          (rows[U2]['idle'], rows[U2]['tables'][0]['why'], rows[U1]['idle']), ('users', 'row-gone', ''))
    with open(config, encoding='utf-8') as handle:
        text = handle.read()
    off = os.path.join(tmp, 'off.xml')
    with open(off, 'w', encoding='utf-8') as handle:
        handle.write(text.replace('<TrafficPriority><general><enabled>1</enabled>', '<TrafficPriority><general><enabled>0</enabled>', 1))
    rows_off = {c['uuid']: c for c in status.status(off, rules, PF, project, None, errors, counts=counts,
                                                    installed={'identity': True, 'appcontrol': True})['classes']}
    check('status: Traffic Priority off - no class idle, as the next filter reload writes no class\'s rule at all (PY2)',
          (rows_off[U2]['idle'], rows_off[U2]['tables'][0]['why']), ('', 'row-gone'))
    check('status: whether os-useridentity and os-appcontrol are installed, as given', got['others'],
          {'identity': True, 'appcontrol': True})
    check('status: their models looked for where they install them', (status.sources.IDENTITY_MODEL,
                                                                     status.sources.APPCONTROL_MODEL),
          ('/usr/local/opnsense/mvc/app/models/OPNsense/UserIdentity/UserIdentity.xml',
           '/usr/local/opnsense/mvc/app/models/OPNsense/AppControl/AppControl.xml'))
    # os-appcontrol removed, its settings and an alias of its left: the line of the Classes tab and each item's
    # reason agree - both read its model's file (P6)
    got = status.status(config, rules, PF, project, None, errors, counts=counts,
                        installed={'identity': True, 'appcontrol': False})
    check('status: Application Control not installed, its settings left - its items say so, as the Classes tab does',
          (got['others'], [(i['name'], i['table'], i['why']) for i in got['classes'][0]['tables']]),
          ({'identity': True, 'appcontrol': False}, [('alice', 'uid_alice', ''), ('Zoom', '', 'no-appcontrol'),
                                                     ('Netflix', '', 'no-appcontrol'), ('VoIP', '', 'no-appcontrol')]))
    got = status.status(config, rules, PF, project, None, errors, counts=counts)
    check('status: neither installed here, by their files - the Classes tab and every item say so',
          (got['others'], sorted({i['why'] for c in got['classes'] for i in c['tables']})),
          ({'identity': False, 'appcontrol': False}, ['no-appcontrol', 'no-identity']))
    check('status: pf holding no such table - no count', [i['count'] for i in status.status(
        config, rules, PF, project, None, errors, counts=lambda t: None,
        installed={'identity': True, 'appcontrol': True})['classes'][0]['tables']], [None, None, None, None])
    hw = status.status(config, placed, PF, project, None, errors, model=xgs, result=kept, counts=counts)['hardware']
    check('status: the switch - a class of users with no table now, which the last reload did not record as left idle: '
          'no place', (hw['classes'][U2]['why'], [d['dscp'] for d in hw['dscps']]), ('rule', [46]))
    recorded = os.path.join(tmp, 'recorded.debug')
    with open(placed, encoding='utf-8') as handle:
        text = handle.read()
    with open(recorded, 'w', encoding='utf-8') as handle:
        handle.write(text + '# match in inet from {any} to {any} label "trafficpriority-idle-%s" # Traffic Priority: Gone - '
                     'makes no rule: no table for its groups and users now: row-gone\n' % U2)
    hw = status.status(config, recorded, PF, project, None, errors, model=xgs, result=kept, counts=counts)['hardware']
    check('status: the switch - the class the reload left idle, by its record, keeps its place after the one the file holds',
          (hw['classes'][U2]['why'], hw['classes'][U2]['idle'], [d['dscp'] for d in hw['dscps']]), ('hardware', True, [46, 34]))

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
