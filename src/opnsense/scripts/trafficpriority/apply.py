#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""
The switch's queues for Traffic Priority's classes, and for what of Firewall: Shaper the switch can
follow, on an XGS 3300 with os-xgs-npu: what to set decided here (hardware.py, shaper_map.py), written
into os-xgs-npu's settings file for the switch, /var/db/os-xgs-npu/switch-qos.json, and set by its
switch_qos.py - which keeps what it found, puts it back, and sets it again after every boot of the
coprocessor. Firewall: Shaper is read and never written.

    apply.py            the settings file written and the switch set; with Traffic Priority off, or
                        nothing for the switch, what this plugin set put back
    apply.py clear      what this plugin set put back as found - its entries alone - the settings file
                        removed first (Traffic Priority's removal)
    apply.py plan       what apply would set, as JSON; nothing written

It prints one JSON object, {"status": "ok" | "failed", "message": ...}, and keeps the outcome for the
page in /var/db/os-trafficpriority/hardware.json - "running" from its start, so that the page, which
starts it in the background after the filter reload and goes on, can say so until it ends.

THE PLACES COME WITH THE FILTER RELOAD. While a class has a place in the switch, the rules hook writes
before every class's rule the one that sets every IPv4 connection's DSCP to 0, both ways
(OPNsense\\TrafficPriority\\Hardware); the switch is given the classes' DSCPs only while the rules file
pf was given holds it, from the classes it holds a rule for (hardware.from_rules(), places_of()) - and
from those the reload left idle, their groups and users, or applications and categories, with no table,
which keep their place as the hook keeps it: the reload records each in the same file, as a line pf never
reads (hardware.idle_in()). When pf refused that rule set, the switch is left as it is: the rules pf still
holds are the set before it.

WHERE NOTHING IS SET: without os-xgs-npu (a plain OPNsense: pf alone marks), or with an os-xgs-npu that
has no switch tool yet; on the XGS 136 family, whose switch os-xgs-npu only reads (its bus is shared
with the network agent, and host reads have taken ports down there - os-xgs-npu #639, #706); on the
models of the XGS 3300's family nothing was run on; and on a model whose switch it does not know. When
a minimum would sit beside a strict class, or the minimums pass 100, nothing either - and what this
plugin set before is put back. The page says which.

ONLY ITS OWN. The settings file names its owner; one that another plugin wrote is not overwritten and
not cleared here. Putting back always removes this plugin's settings file first, so that nothing - the
boot hook either - sets the switch from it again, whatever the put-back does.
"""

import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hardware  # noqa: E402
import shaper_map  # noqa: E402

CONFIG = os.environ.get('TP_CONFIG', '/conf/config.xml')
PY = os.environ.get('TP_PYTHON', '/usr/local/bin/python3')
TOOL = os.environ.get('TP_SWITCH_TOOL', '/usr/local/opnsense/scripts/xgs/switch_qos.py')
SETTINGS = os.environ.get('TP_SWITCH_SETTINGS', '/var/db/os-xgs-npu/switch-qos.json')
STATE = os.environ.get('TP_SWITCH_STATE', '/var/db/os-xgs-npu/switch-qos.state')
RESULT = os.environ.get('TP_RESULT', '/var/db/os-trafficpriority/hardware.json')
RULES = os.environ.get('TP_RULES', '/tmp/rules.debug')          # what the last filter reload gave pf
ERRORS = os.environ.get('TP_RULES_ERROR', '/tmp/rules.error')   # why pf refused it, when it did
# os-xgs-npu's model: installed, but without the switch tool, it is an os-xgs-npu older than the tool
PROJECT = os.environ.get('TP_PROJECT', '/usr/local/opnsense/mvc/app/models/OPNsense/XGS/XGS.xml')
OWNER = 'os-trafficpriority'
TIMEOUT = int(os.environ.get('TP_SWITCH_TIMEOUT', '600'))


def tool(*args, timeout=None):
    """(exit, what it printed, what it said on stderr) of os-xgs-npu's switch tool; None when it is
    not here. A run that does not end in time is said as such."""
    timeout = timeout or TIMEOUT
    if not os.path.isfile(TOOL):
        return None
    try:
        done = subprocess.run([PY, TOOL] + list(args), stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              errors='replace', timeout=timeout)
    except subprocess.TimeoutExpired:
        return 1, '', 'the switch tool did not finish within %d s' % timeout
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, '', 'the switch tool could not be run: %s' % exc
    return done.returncode, done.stdout, done.stderr


def can():
    """What the switch tool says of this model, or None without os-xgs-npu's switch tool."""
    got = tool('can', timeout=60)
    if got is None or got[0] != 0:
        return None
    try:
        out = json.loads(got[1])
    except ValueError:
        return None
    return out if isinstance(out, dict) else None


def rules_text(path=None):
    try:
        with open(path or RULES, encoding='utf-8', errors='replace') as handle:
            return handle.read()
    except OSError:
        return ''


def rules_refused(rules=None, errors=None):
    """Whether pf refused the rule set the last filter reload wrote (status.py's refused())."""
    try:
        return os.stat(errors or ERRORS).st_mtime_ns >= os.stat(rules or RULES).st_mtime_ns
    except OSError:
        return False


def decide(root, model, text=''):
    """What the switch is given, from config.xml's root element, what the switch tool says of this
    model and the rules file of the last filter reload: {'why_not', 'follow', 'plan', 'shaper', 'conf',
    'refused'}. why_not is '' when the switch is set, else plugin-off, no-project (no os-xgs-npu),
    no-tool (an os-xgs-npu without the switch tool), read-only (the XGS 136 family), untested-model
    (one of the XGS 3300's family nothing was run on) or no-switch; refused is the plan's - mix or over;
    conf is None when either is set, or nothing is for the switch."""
    on, follow, classes = hardware.read_classes(root)
    if not on:
        why_not = 'plugin-off'
    elif model is None:
        why_not = 'no-tool' if os.path.exists(PROJECT) else 'no-project'
    elif not model.get('writes'):
        why_not = model.get('why') or 'no-switch'
    else:
        why_not = ''
    cleared, written = hardware.from_rules(text)
    # a class the last filter reload left idle - its groups and users, or applications and categories,
    # with no table, nothing else wrong with it - keeps its place, as that reload kept it: the same file
    # records it, so this cannot take it from config.xml as saved since, nor give one to a class the
    # reload gave none
    idle = hardware.idle_in(text)
    places = hardware.places_of(classes, written, cleared, idle)
    marked = {hardware.dscp(c.get('dscp')) for c in hardware.ordered(classes)} - {None}
    first = hardware.plan(classes, places, written, idle=idle)
    own_minimum = {d['dscp'] for d in first['dscps']} if any(
        r['minimum'] is not None and r['why'] == 'hardware' for r in first['classes'].values()) else set()
    devices = (model or {}).get('devices') or {}
    followed = shaper_map.follow(shaper_map.read(root), marked, [d['dscp'] for d in first['dscps']], own_minimum,
                                 devices, shaper_map.interfaces(root),
                                 why_not=why_not or ('' if follow else 'follow-off'))
    following = follow and not why_not
    plan = hardware.plan(classes, places, written, followed['shares'] if following else {}, idle=idle)
    rows = shaper_map.settle(followed['rules'], plan)
    conf = None
    if not why_not and not plan['refused']:
        conf = {'owner': OWNER,
                'classes': [{'dscp': d['dscp'], 'mask': 63, 'queue': d['queue']} for d in plan['dscps']],
                'scheduling': {'*': plan['mode']} if plan['dscps'] else {},
                'limits': followed['limits'] if following else {}}
        if plan['weights'] is not None:
            conf['weights'] = plan['weights']
        if not conf['classes'] and not conf['limits']:
            conf = None
    return {'why_not': why_not, 'follow': follow, 'plan': plan, 'shaper': rows, 'conf': conf,
            'refused': plan['refused'] if not why_not else ''}


def owner_of(path):
    try:
        with open(path, encoding='utf-8') as f:
            got = json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return ''
    return str(got.get('owner', '')) if isinstance(got, dict) else ''


def ours():
    """Whether what the switch tool keeps or is asked for is this plugin's."""
    return OWNER in (owner_of(SETTINGS), owner_of(STATE))


def clear():
    """(status, message): this plugin's settings file removed first - nothing sets the switch from it
    again - then what it set put back, through the switch tool."""
    if not ours():
        return 'nothing', ''
    if owner_of(SETTINGS) == OWNER:
        os.remove(SETTINGS)
    got = tool('clear')
    if got is None:
        return 'nothing', ''
    if got[0] == 0:
        return 'cleared', last(got)
    return 'failed', last(got)


def last(got):
    """The tool's last line worth saying: its refusal or failure, else what it did; never empty."""
    lines = [l.strip() for l in (got[2] or '').splitlines() if l.strip()]
    lines = lines or [l.strip() for l in (got[1] or '').splitlines() if l.strip()]
    if lines:
        return lines[-1]
    return 'the switch tool ended (exit %d) without a word' % got[0] if got[0] else ''


def write_settings(conf):
    os.makedirs(os.path.dirname(SETTINGS), exist_ok=True)
    with open(SETTINGS + '.new', 'w', encoding='utf-8') as f:
        json.dump(conf, f, indent=1, sort_keys=True)
        f.write('\n')
    os.replace(SETTINGS + '.new', SETTINGS)


def keep(result):
    os.makedirs(os.path.dirname(RESULT), exist_ok=True)
    with open(RESULT + '.new', 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=1, sort_keys=True)
        f.write('\n')
    os.replace(RESULT + '.new', RESULT)


def now():
    return time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())


def apply():
    root = hardware.config(CONFIG)
    if root is None:
        return {'status': 'failed', 'message': 'config.xml could not be read'}
    keep({'status': 'running', 'said': '', 'time': now()})
    if rules_refused():
        said = 'pf refused the rule set of the last filter reload: the switch is left as it is'
        keep({'status': 'refused', 'refused': 'rules', 'said': said, 'time': now()})
        return {'status': 'failed', 'message': said}
    decided = decide(root, can(), rules_text())
    status, said = 'nothing', ''
    if decided['conf'] is None:
        status, said = clear()
        if decided['refused'] and status != 'failed':
            status, said = 'refused', decided['refused']
    elif owner_of(SETTINGS) not in (None, OWNER):
        status, said = 'refused', 'the switch\'s settings file is another plugin\'s (%s): not overwritten' % owner_of(SETTINGS)
    else:
        write_settings(decided['conf'])
        got = tool('apply')
        if got is None:
            status, said = 'failed', 'os-xgs-npu\'s switch tool is not here'
        else:
            status, said = ('applied' if got[0] == 0 else 'failed'), last(got)
    keep(dict(decided, status=status, said=said, time=now()))
    if status in ('failed', 'refused'):
        return {'status': 'failed', 'message': said}
    return {'status': 'ok', 'message': status}


def main(argv):
    if argv == ['plan']:
        root = hardware.config(CONFIG)
        print(json.dumps(decide(root, can(), rules_text()) if root is not None else
                         {'error': 'config.xml could not be read'}, sort_keys=True))
        return 0
    if argv == ['clear']:
        status, said = clear()
        if status != 'failed':
            try:
                os.remove(RESULT)
            except FileNotFoundError:
                pass
        print(json.dumps({'status': 'failed' if status == 'failed' else 'ok', 'message': said or status}))
        return 1 if status == 'failed' else 0
    if argv:
        print('usage: apply.py [clear | plan]', file=sys.stderr)
        return 64
    out = apply()
    print(json.dumps(out))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
