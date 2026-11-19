#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""shaper_map.py and apply.py's decision: Firewall: Shaper followed into the switch's queues, against
configurations of Firewall: Shaper written here as its model keeps them in config.xml - pipes with a
bandwidth and a mask, queues with weights, rules by interface, direction, addresses, ports and DSCP.
For each rule: what the switch takes - a front port's egress limit from a rule that sends everything
leaving that port into a pipe, a DSCP's queue and a part of every port from a queue's weight - and
what stays with the host, and why: the way in, a limit for each address, an interface not behind the
switch, a rate the switch cannot set, a port an earlier rule limits, a rule that matches no DSCP or
more than one, a DSCP no class marks or one marked by pf alone, a class's own minimum first, a part
taken by an earlier rule or past 100 percent, a pipe's limit for one class. And what the switch is
given, apply.py's settings for os-xgs-npu's switch tool: nothing while Traffic Priority is off, without
os-xgs-npu, on the XGS 136 family, or - for Firewall: Shaper - while following it is off.

    python3 tools/test-shaper-map.py"""
import os
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'trafficpriority'))
import apply  # noqa: E402
import shaper_map  # noqa: E402

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


# an XGS 3300 as os-xgs-npu's switch tool describes it: F1 and F2 (oxp0, oxp1) on the coprocessor's own
# MACs, Port1 to Port8 and F3, F4 behind the switch
XGS3300 = {'family': 'octeontx', 'writes': True, 'why': '', 'entries': 2,
           'ports': ['Port%d' % n for n in range(1, 9)] + ['F3', 'F4'],
           'devices': dict({'oxp%d' % (n + 1): 'Port%d' % n for n in range(1, 9)}, oxp10='F3', oxp11='F4')}
XGS136 = {'family': 'armada', 'writes': False, 'why': 'read-only', 'entries': 2, 'ports': [], 'devices': {}}
IFACES = {'wan': 'oxp3', 'lan': 'oxp2', 'opt1': 'oxp0', 'opt2': 'oxp9_vlan10'}


def node(tag, uuid=None, **fields):
    n = ET.Element(tag)
    if uuid:
        n.set('uuid', uuid)
    for k, v in fields.items():
        ET.SubElement(n, k).text = str(v)
    return n


def config(classes=(), pipes=(), queues=(), rules=(), on='1', follow='1'):
    root = ET.Element('opnsense')
    ifs = ET.SubElement(root, 'interfaces')
    for name, dev in IFACES.items():
        ET.SubElement(ifs, name).append(node('if')) or None
        ifs.find(name).find('if').text = dev
    opn = ET.SubElement(root, 'OPNsense')
    tp = ET.SubElement(opn, 'TrafficPriority')
    tp.append(node('general', enabled=on, follow_shaper=follow))
    cl = ET.SubElement(tp, 'classes')
    for c in classes:
        cl.append(node('class', **c))
    ts = ET.SubElement(opn, 'TrafficShaper')
    for path, items in (('pipes', pipes), ('queues', queues), ('rules', rules)):
        holder = ET.SubElement(ts, path)
        for item in items:
            item = dict(item)
            holder.append(node(path[:-1], item.pop('uuid'), **item))
    return root


def pipe(uuid, bw, metric='Mbit', mask='none', enabled='1', description=None):
    return {'uuid': uuid, 'number': '1', 'enabled': enabled, 'bandwidth': bw, 'bandwidthMetric': metric, 'mask': mask,
            'description': description or uuid}


def queue(uuid, pipe_uuid, weight, enabled='1'):
    return {'uuid': uuid, 'number': '1', 'enabled': enabled, 'pipe': pipe_uuid, 'weight': weight, 'mask': 'none',
            'description': uuid}


def rule(uuid, target, sequence='1', interface='wan', direction='out', proto='ip', dscp='', source='any',
         destination='any', enabled='1', **more):
    r = {'uuid': uuid, 'enabled': enabled, 'sequence': sequence, 'interface': interface, 'proto': proto,
         'source': source, 'source_not': '0', 'src_port': 'any', 'destination': destination, 'destination_not': '0',
         'dst_port': 'any', 'direction': direction, 'target': target, 'description': uuid}
    if dscp:
        r['dscp'] = dscp
    r.update(more)
    return r


def voice(minimum='', dscp='46', uuid='c1', sequence='100'):
    c = {'uuid': uuid, 'enabled': '1', 'sequence': sequence, 'description': 'Voice', 'dscp': dscp,
         'ipprotocol': 'inet'}
    if minimum:
        c['minimum'] = minimum
    return c


def decide(model=XGS3300, **kw):
    return apply.decide(config(**kw), model)


def rows(decided):
    return {r['uuid']: r for r in decided['shaper']}


def why(row):
    return [h['why'] for h in row['host']]


# ---- a pipe's bandwidth as a port's egress limit ----
d = decide(classes=[voice()], pipes=[pipe('p100', 100)], rules=[rule('all-out', 'p100')])
r = rows(d)['all-out']
check('a rule sending everything leaving WAN (Port2) into a 100 Mbit/s pipe: Port2\'s egress limit',
      (r['hardware'], r['host'], d['conf']['limits']), ([{'what': 'limit', 'port': 'Port2', 'kbit': 100000}], [],
                                                       {'Port2': 100000}))
check('the settings for the switch tool: the class, the scheduling, the limit; no weights',
      d['conf'], {'owner': 'os-trafficpriority', 'classes': [{'dscp': 46, 'mask': 63, 'queue': 7}],
                  'scheduling': {'*': 1}, 'limits': {'Port2': 100000}})
for metric, bw, kbit in (('Kbit', 512, 512), ('Gbit', 1, 1000000), ('bit', 900000000, 900000)):
    got = decide(pipes=[pipe('p', bw, metric)], rules=[rule('r', 'p')])
    check('a pipe of %d %s: %d kbit/s' % (bw, metric, kbit), got['conf']['limits'] if got['conf'] else None,
          {'Port2': kbit})
r = rows(decide(pipes=[pipe('p100', 100)], rules=[rule('both', 'p100', direction='')]))['both']
check('both ways: the way out limited, the way in stays with the host', ([h['what'] for h in r['hardware']], why(r)),
      (['limit'], ['way-in']))
d = decide(pipes=[pipe('p100', 100)], rules=[rule('in', 'p100', direction='in')])
check('the way in alone: stays with the host, nothing for the switch', (why(rows(d)['in']), d['conf']), (['way-in'], None))
check('a pipe with a mask - a bandwidth for each address: stays',
      why(rows(decide(pipes=[pipe('p', 100, mask='src-ip')], rules=[rule('r', 'p')]))['r']), ['per-host'])
check('a rule on F1, on the coprocessor\'s own MAC: stays',
      why(rows(decide(pipes=[pipe('p', 100)], rules=[rule('r', 'p', interface='opt1')]))['r']), ['not-switch-port'])
check('a rule on a VLAN: not a front port behind the switch',
      why(rows(decide(pipes=[pipe('p', 100)], rules=[rule('r', 'p', interface='opt2')]))['r']), ['not-switch-port'])
check('a pipe below the switch\'s smallest step, 64 kbit/s: stays',
      why(rows(decide(pipes=[pipe('p', 32, 'Kbit')], rules=[rule('r', 'p')]))['r']), ['rate'])
d = decide(pipes=[pipe('p100', 100), pipe('p50', 50)], rules=[rule('second', 'p50', sequence='20'),
                                                                rule('first', 'p100', sequence='10')])
check('two rules on one port: the first by sequence limits it, the other stays',
      (d['conf']['limits'], [h for h in rows(d)['second']['host']]),
      ({'Port2': 100000}, [{'why': 'port-taken', 'port': 'Port2', 'by': 'first'}]))
check('the rules in their sequence\'s order', [r['uuid'] for r in d['shaper']], ['first', 'second'])
r = rows(decide(pipes=[pipe('p', 100)], rules=[rule('r', 'p', source='192.0.2.0/24')]))['r']
check('a rule for some addresses into a pipe, no DSCP: the switch cannot tell them; the limit is the class\'s',
      (r['hardware'], why(r)), ([], ['no-dscp', 'class-limit']))
for field, value in (('proto', 'tcp'), ('dst_port', '443'), ('iplen', '200'), ('interface2', 'lan'),
                     ('destination_not', '1')):
    r = rows(decide(pipes=[pipe('p', 100)], rules=[rule('r', 'p', **{field: value})]))['r']
    check('a rule with %s %s: not the whole port' % (field, value), r['hardware'], [])
check('a pipe switched off: its rule not followed',
      why(rows(decide(pipes=[pipe('p', 100, enabled='0')], rules=[rule('r', 'p')]))['r']), ['target-off'])
check('a rule switched off', why(rows(decide(pipes=[pipe('p', 100)], rules=[rule('r', 'p', enabled='0')]))['r']), ['off'])
check('a rule whose pipe is gone', why(rows(decide(rules=[rule('r', 'nothing')]))['r']), ['target-off'])

# ---- a queue's weight as a part of every port, for a DSCP a class marks and has a place for ----
shaper = dict(pipes=[pipe('p', 100)], queues=[queue('qv', 'p', 70), queue('qb', 'p', 30)])
d = decide(classes=[voice()], rules=[rule('ef', 'qv', dscp='ef'), rule('rest', 'qb', sequence='2')], **shaper)
r = rows(d)['ef']
check('EF into a queue of weight 70 against 30: 70 percent of every port for DSCP 46, queue 7 weighted',
      r['hardware'], [{'what': 'queue', 'dscp': 46, 'queue': 7, 'kind': 'weighted'},
                      {'what': 'share', 'dscp': 46, 'percent': 70, 'queue': 7, 'kind': 'weighted'}])
check('...its pipe\'s 100 Mbit/s for EF alone stays with the host', r['host'], [{'why': 'class-limit', 'kbit': 100000}])
check('...the settings: all weighted, 70 turns for queue 7, 30 for the rest',
      (d['conf']['scheduling'], d['conf']['weights'].count(7), d['conf']['weights'].count(0), 'limits' in d['conf']),
      ({'*': 0}, 70, 30, True))
check('...the catch-all rule into the other queue: everything leaving WAN through the pipe - Port2 limited',
      (rows(d)['rest']['hardware'], d['conf']['limits']), ([{'what': 'limit', 'port': 'Port2', 'kbit': 100000}],
                                                           {'Port2': 100000}))
d = decide(classes=[voice(minimum='20')], rules=[rule('ef', 'qv', dscp='ef')], **shaper)
check('a class\'s own minimum before the rule\'s part', ([h['what'] for h in rows(d)['ef']['hardware']],
                                                         why(rows(d)['ef'])[0], d['conf']['weights'].count(7)),
      (['queue'], 'minimum-wins', 20))
d = decide(classes=[voice(), voice(uuid='c2', dscp='34', minimum='50')],
           rules=[rule('ef', 'qv', dscp='ef')], **shaper)
check('a part that would take the parts past 100 (50 + 70): stays, EF strict',
      ([h['what'] for h in rows(d)['ef']['hardware']], 'share-over' in why(rows(d)['ef']), d['plan']['dscps'][0]['kind']),
      (['queue'], True, 'strict'))
d = decide(classes=[voice()], rules=[rule('a', 'qv', dscp='ef', sequence='1'), rule('b', 'qb', dscp='ef', sequence='2')],
           **shaper)
check('two rules giving EF a part: the first\'s taken', (rows(d)['b']['host'][0], d['conf']['weights'].count(7)),
      ({'why': 'share-taken', 'dscp': 46, 'by': 'a', 'percent': 30}, 70))
d = decide(classes=[voice()], pipes=[pipe('p', 100)], queues=[queue('alone', 'p', 50)],
           rules=[rule('r', 'alone', dscp='ef')])
check('the only queue of its pipe: its weight shares nothing; EF strict',
      (why(rows(d)['r'])[0], d['plan']['dscps'][0]['kind']), ('one-queue', 'strict'))
d = decide(classes=[voice()], rules=[rule('r', 'qv', dscp='ef', source='192.0.2.10')], **shaper)
check('a rule by a DSCP and an address: the switch picks out the DSCP alone',
      ([h['what'] for h in rows(d)['r']['hardware']], why(rows(d)['r'])[0]), (['queue', 'share'], 'dscp-only'))
d = decide(classes=[voice()], pipes=[pipe('p', 20)], rules=[rule('r', 'p', dscp='ef')])
check('EF into a pipe: its queue in the switch, the pipe\'s limit for EF alone stays',
      (rows(d)['r']['hardware'], why(rows(d)['r'])), ([{'what': 'queue', 'dscp': 46, 'queue': 7, 'kind': 'strict'}],
                                                      ['class-limit']))
check('a DSCP no class marks', rows(decide(classes=[voice()], rules=[rule('r', 'qv', dscp='af41')], **shaper))['r']['host'],
      [{'why': 'unmarked', 'dscp': 34}])
third = [voice(), voice(uuid='c2', dscp='34'), voice(uuid='c3', dscp='40')]
check('a DSCP marked by pf alone: the switch\'s two places taken',
      rows(decide(classes=third, rules=[rule('r', 'qv', dscp='cs5')], **shaper))['r']['host'], [{'why': 'pf-only', 'dscp': 40}])
check('more than one DSCP in a rule', why(rows(decide(classes=third, rules=[rule('r', 'qv', dscp='ef,af41')],
                                                      **shaper))['r']), ['dscps'])
check('Best Effort: queue 0 already', why(rows(decide(classes=[voice()], rules=[rule('r', 'qv', dscp='be')],
                                                      **shaper))['r']), ['best-effort'])
check('a DSCP name not known', why(rows(decide(classes=[voice()], rules=[rule('r', 'qv', dscp='xx')], **shaper))['r']),
      ['dscp-name'])
check('a share: the queue\'s weight against the others of its pipe switched on',
      shaper_map.share({'queues': {'a': queue('a', 'p', 70), 'b': queue('b', 'p', 30), 'c': queue('c', 'p', 900, '0'),
                                   'd': queue('d', 'other', 10)}}, queue('a', 'p', 70)), 70)

# ---- nothing for the switch ----
everything = dict(classes=[voice()], rules=[rule('ef', 'qv', dscp='ef'), rule('all', 'p', sequence='3')], **shaper)
d = decide(follow='0', **everything)
check('following Firewall: Shaper off: every rule says so; the classes still go to the switch',
      ({why(r)[0] for r in d['shaper']}, d['conf']['limits'], 'weights' in d['conf'], d['conf']['classes']),
      ({'follow-off'}, {}, False, [{'dscp': 46, 'mask': 63, 'queue': 7}]))
d = decide(on='0', **everything)
check('Traffic Priority off: nothing for the switch, every rule says so',
      (d['why_not'], d['conf'], {why(r)[0] for r in d['shaper']}), ('plugin-off', None, {'plugin-off'}))
d = decide(model=XGS136, **everything)
check('the XGS 136 family: os-xgs-npu only reads its switch - nothing given, said',
      (d['why_not'], d['conf'], {why(r)[0] for r in d['shaper']}), ('read-only', None, {'read-only'}))
d = decide(model=None, **everything)
check('no os-xgs-npu: pf alone', (d['why_not'], d['conf']), ('no-project', None))
d = decide(classes=[voice(dscp='0')])
check('nothing to give the switch: no settings', (d['why_not'], d['conf']), ('', None))
check('Firewall: Shaper never set: no rule', decide(classes=[voice()])['shaper'], [])

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
