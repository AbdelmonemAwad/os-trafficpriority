#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""
Firewall: Shaper followed into the switch's queues, where the switch can do what a rule does - read
from config.xml (OPNsense/TrafficShaper: pipes, queues, rules) and never written. For every rule, what
of it the switch takes and what stays with the host, and why; apply.py gives the switch what is taken,
and the page lists every rule with both.

WHAT THE SWITCH CAN TAKE (os-xgs-npu's switch_qos.py, measured on the XGS 3300; hardware.py says how):
  - a DSCP: the switch tells frames apart by their DSCP alone, and two DSCPs have a queue of their
    own - those of Traffic Priority's classes, the first two in the page's order. So a rule is
    followed only where it matches by one DSCP, and that DSCP is one a class marks and has a place;
  - a share: a rule into a queue of Firewall: Shaper gives that DSCP the queue's weight as a part of
    the port - its weight against the weights of the other queues of its pipe. One sequence of weights
    serves the whole chip, so the part holds on every front port behind the switch, both ways. A
    class's own minimum comes first; the parts of all are taken while they add up to 100 % at most;
  - a port's limit: the switch limits what leaves a port, all of it, in UMSD's steps (1 Mbit/s up to
    100 Mbit/s, 10 Mbit/s up to 1 Gbit/s). So a pipe's bandwidth is followed only from a rule that
    sends everything going out of a front port behind the switch into the pipe: any protocol, any
    source and destination, no port, no DSCP, no packet length, one interface, the way out (or both
    ways, whose way in stays with the host), and a pipe without a mask - not one bandwidth for each
    address.

WHAT STAYS WITH THE HOST, always: the rule itself. OPNsense's Shaper is ipfw on the host, and
os-xgs-npu keeps every connection an enabled Shaper rule names with the host, off the hardware
(its shaper-3300-2026-10-20 measurement), so the host shapes them as before; what is followed into the
switch is added at the ports, not taken from the host. The rest of a pipe - its scheduler, CoDel or
PIE, delay, queue size, buckets - the switch has no part of.
"""

ROLE = {'pipe', 'queue'}
# Firewall: Shaper's DSCP names (TrafficShaper.xml), by number
DSCP = {'be': 0, 'ef': 46, 'af11': 10, 'af12': 12, 'af13': 14, 'af21': 18, 'af22': 20, 'af23': 22,
        'af31': 26, 'af32': 28, 'af33': 30, 'af41': 34, 'af42': 36, 'af43': 38, 'cs1': 8, 'cs2': 16,
        'cs3': 24, 'cs4': 32, 'cs5': 40, 'cs6': 48, 'cs7': 56}
METRIC = {'bit': 0.001, 'Kbit': 1, 'Mbit': 1000, 'Gbit': 1000000}
SMALLEST = 64               # kbit/s: UMSD's smallest step
LARGEST = 10000000          # kbit/s: UMSD's largest rate


def _items(node, path):
    out = []
    if node is None:
        return out
    for item in node.findall(path):
        fields = {child.tag: (child.text or '').strip() for child in item}
        fields['uuid'] = (item.get('uuid') or '').lower()
        out.append(fields)
    return out


def read(root):
    """Firewall: Shaper's pipes and queues by UUID, and its rules in config.xml's order."""
    own = root.find('OPNsense/TrafficShaper') if root is not None else None
    return {'pipes': {p['uuid']: p for p in _items(own, 'pipes/pipe')},
            'queues': {q['uuid']: q for q in _items(own, 'queues/queue')},
            'rules': _items(own, 'rules/rule')}


def interfaces(root):
    """OPNsense's interfaces, by their name in the rules (wan, lan, opt1), with their devices."""
    node = root.find('interfaces') if root is not None else None
    if node is None:
        return {}
    return {child.tag: (child.findtext('if') or '').strip() for child in node}


def kbit(pipe):
    """A pipe's bandwidth in kbit/s, a whole number; None when it cannot be read."""
    try:
        bandwidth = int(pipe.get('bandwidth') or '')
    except ValueError:
        return None
    factor = METRIC.get(pipe.get('bandwidthMetric') or 'Kbit')
    if factor is None or bandwidth < 1:
        return None
    return int(bandwidth * factor)


def sequence_of(rule):
    value = rule.get('sequence') or ''
    return int(value) if value.isdigit() else 1


def is_any(value):
    return (value or 'any').strip().lower() in ('', 'any')


def dscps(rule):
    """The DSCPs a rule matches, as numbers; None for a name this does not know."""
    out = []
    for name in (rule.get('dscp') or '').split(','):
        name = name.strip().lower()
        if not name:
            continue
        if name not in DSCP:
            return None
        out.append(DSCP[name])
    return out


def whole_port(rule):
    """Whether a rule takes everything on its interface: any protocol, source and destination, no port,
    no DSCP, no packet length, no second interface."""
    return ((rule.get('proto') or 'ip') == 'ip' and is_any(rule.get('source')) and is_any(rule.get('destination'))
            and (rule.get('source_not') or '0') != '1' and (rule.get('destination_not') or '0') != '1'
            and is_any(rule.get('src_port')) and is_any(rule.get('dst_port')) and not (rule.get('dscp') or '')
            and not (rule.get('iplen') or '') and not (rule.get('interface2') or ''))


def target_of(shaper, rule):
    """(kind, the pipe or queue, its pipe) a rule sends to; kind '' when neither is there."""
    uuid = (rule.get('target') or '').lower()
    if uuid in shaper['pipes']:
        return 'pipe', shaper['pipes'][uuid], shaper['pipes'][uuid]
    if uuid in shaper['queues']:
        queue = shaper['queues'][uuid]
        return 'queue', queue, shaper['pipes'].get((queue.get('pipe') or '').lower())
    return '', None, None


def on(item):
    return item is not None and (item.get('enabled') or '1') == '1'


def share(shaper, queue):
    """A queue's weight as a percent of its pipe's: against the weights of every queue switched on in the
    same pipe; None when it is its pipe's only queue, whose weight shares nothing."""
    try:
        weight = int(queue.get('weight') or '100')
    except ValueError:
        return None
    pipe = (queue.get('pipe') or '').lower()
    total, count = 0, 0
    for q in shaper['queues'].values():
        if (q.get('pipe') or '').lower() == pipe and on(q):
            try:
                total += int(q.get('weight') or '100')
            except ValueError:
                return None
            count += 1
    if count < 2 or total <= 0:
        return None
    return max(1, int(round(100.0 * weight / total)))


def follow(shaper, marked, places, own_minimum, switch_ports, names, why_not=''):
    """Every rule of Firewall: Shaper, in its sequence's order, with what the switch takes of it and
    what stays with the host: {'rules': [row, ...], 'shares': {dscp: percent}, 'limits': {port: kbit}}.

    marked: the DSCPs the classes switched on mark; places: the DSCPs with a queue of their own, in
    order (hardware.places()); own_minimum: those of places whose classes give a minimum; switch_ports:
    {device: front-port name} of the ports behind the switch; names: OPNsense's interfaces with their
    devices; why_not: '' when the switch is followed into, else why nothing is (follow-off, plugin-off,
    model). A share is a proposal here: hardware.plan() takes it while the parts fit, and settle() says
    which it took."""
    rules = sorted(enumerate(shaper['rules']), key=lambda ir: (sequence_of(ir[1]), ir[0]))
    out, shares, limits = [], {}, {}
    share_from, limit_from = {}, {}
    for _, rule in rules:
        kind, target, pipe = target_of(shaper, rule)
        row = {'uuid': rule['uuid'], 'sequence': sequence_of(rule), 'description': rule.get('description') or '',
               'interface': rule.get('interface') or '', 'interface2': rule.get('interface2') or '',
               'direction': rule.get('direction') or '', 'target': (target or {}).get('description') or '',
               'target_kind': kind, 'hardware': [], 'host': []}
        out.append(row)
        if not on(rule):
            row['host'].append({'why': 'off'})
            continue
        if target is None or not on(target) or not on(pipe):
            row['host'].append({'why': 'target-off'})
            continue
        if why_not:
            row['host'].append({'why': why_not})
            continue
        rate = kbit(pipe)
        if whole_port(rule):
            device = names.get(row['interface'], '')
            port = switch_ports.get(device)
            if (pipe.get('mask') or 'none') != 'none':
                row['host'].append({'why': 'per-host', 'kbit': rate})
            elif port is None:
                row['host'].append({'why': 'not-switch-port', 'kbit': rate})
            elif rate is None or rate < SMALLEST or rate > LARGEST:
                row['host'].append({'why': 'rate', 'kbit': rate})
            elif row['direction'] == 'in':
                row['host'].append({'why': 'way-in', 'kbit': rate})
            elif port in limits:
                row['host'].append({'why': 'port-taken', 'port': port, 'by': limit_from[port]})
            else:
                limits[port] = rate
                limit_from[port] = row['description'] or row['uuid']
                row['hardware'].append({'what': 'limit', 'port': port, 'kbit': rate})
                if row['direction'] == '':
                    row['host'].append({'why': 'way-in', 'kbit': rate})
            continue
        found = dscps(rule)
        if not found:
            row['host'].append({'why': 'no-dscp' if found == [] else 'dscp-name'})
            if found == [] and rate is not None:
                row['host'].append({'why': 'class-limit', 'kbit': rate})
            continue
        if len(found) > 1:
            row['host'].append({'why': 'dscps', 'dscps': found})
            continue
        d = found[0]
        if d == 0:
            row['host'].append({'why': 'best-effort'})
            continue
        if d not in marked:
            row['host'].append({'why': 'unmarked', 'dscp': d})
            continue
        if d not in places:
            row['host'].append({'why': 'pf-only', 'dscp': d})
            continue
        row['hardware'].append({'what': 'queue', 'dscp': d})
        if not whole_port(dict(rule, dscp='')):
            row['host'].append({'why': 'dscp-only'})
        if kind == 'queue':
            part = share(shaper, target)
            if part is None:
                row['host'].append({'why': 'one-queue'})
            elif d in own_minimum:
                row['host'].append({'why': 'minimum-wins', 'dscp': d, 'percent': part})
            elif d in shares:
                row['host'].append({'why': 'share-taken', 'dscp': d, 'by': share_from[d], 'percent': part})
            else:
                shares[d] = part
                share_from[d] = row['description'] or row['uuid']
                row['hardware'].append({'what': 'share', 'dscp': d, 'percent': part})
        if rate is not None:
            row['host'].append({'why': 'class-limit', 'kbit': rate})
    return {'rules': out, 'shares': shares, 'limits': limits}


def settle(rows, plan):
    """The rows once hardware.plan() has decided: a share it did not take moves to the host, with why;
    each DSCP's queue is named."""
    queue = {d['dscp']: d for d in plan['dscps']}
    for row in rows:
        kept = []
        for item in row['hardware']:
            if item['what'] in ('queue', 'share') and item['dscp'] not in queue:
                continue
            if item['what'] == 'share':
                place = queue[item['dscp']]
                if place['from'] != 'shaper' or place['percent'] != item['percent']:
                    row['host'].append({'why': 'share-over', 'dscp': item['dscp'], 'percent': item['percent']})
                    continue
            if item['what'] in ('queue', 'share'):
                item['queue'] = queue[item['dscp']]['queue']
                item['kind'] = queue[item['dscp']]['kind']
            kept.append(item)
        row['hardware'] = kept
    return rows
