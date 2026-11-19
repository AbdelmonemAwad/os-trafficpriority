#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""
The switch's queues for Traffic Priority's classes, and for what of Firewall: Shaper the switch can
follow, on an XGS appliance with os-xgs-npu: what to set decided here (hardware.py, shaper_map.py),
written into os-xgs-npu's settings file for the switch, /var/db/os-xgs-npu/switch-qos.json, and set by
its switch_qos.py - which keeps what it found, puts it back, and sets it again after every boot of the
coprocessor. Firewall: Shaper is read and never written.

    apply.py            the settings file written and the switch set; with Traffic Priority off, or
                        nothing for the switch, what this plugin set put back
    apply.py clear      what this plugin set put back as found - its entries alone - and the settings
                        file gone (Traffic Priority's removal)
    apply.py plan       what apply would set, as JSON; nothing written

It prints one JSON object, {"status": "ok" | "failed", "message": ...}, and keeps the outcome for the
page in /var/db/os-trafficpriority/hardware.json. The page's Apply runs it after the filter reload.

WHERE NOTHING IS SET: without os-xgs-npu (a plain OPNsense: pf alone marks); on the XGS 136 family,
whose switch os-xgs-npu only reads (its bus is shared with the network agent, and host reads have
taken ports down there - os-xgs-npu #639, #706); and on a model whose switch it does not know. The page
says which.

ONLY ITS OWN. The settings file names its owner; one that another plugin wrote is not overwritten and
not cleared here.
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
# os-xgs-npu's model: installed, but without the switch tool, it is an os-xgs-npu older than the tool
PROJECT = os.environ.get('TP_PROJECT', '/usr/local/opnsense/mvc/app/models/OPNsense/XGS/XGS.xml')
OWNER = 'os-trafficpriority'


def tool(*args, timeout=300):
    """(exit, what it printed, what it said on stderr) of os-xgs-npu's switch tool; None when it is
    not here."""
    if not os.path.isfile(TOOL):
        return None
    try:
        done = subprocess.run([PY, TOOL] + list(args), stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              errors='replace', timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, '', str(exc)
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


def decide(root, model):
    """What the switch is given, from config.xml's root element and what the switch tool says of this
    model: {'why_not', 'follow', 'plan', 'shaper', 'conf'}. why_not is '' when the switch is set, else
    plugin-off, no-project (no os-xgs-npu), no-tool (an os-xgs-npu without the switch tool), read-only
    (the XGS 136 family) or no-switch; conf is None then."""
    on, follow, classes = hardware.read_classes(root)
    if not on:
        why_not = 'plugin-off'
    elif model is None:
        why_not = 'no-tool' if os.path.exists(PROJECT) else 'no-project'
    elif not model.get('writes'):
        why_not = model.get('why') or 'no-switch'
    else:
        why_not = ''
    places, _ = hardware.places(classes)
    marked = {hardware.dscp(c.get('dscp')) for c in hardware.ordered(classes)} - {None}
    first = hardware.plan(classes)
    own_minimum = {d['dscp'] for d in first['dscps'] if d['from'] == 'minimum'}
    devices = (model or {}).get('devices') or {}
    followed = shaper_map.follow(shaper_map.read(root), marked, places, own_minimum, devices,
                                 shaper_map.interfaces(root), why_not=why_not or ('' if follow else 'follow-off'))
    following = follow and not why_not
    plan = hardware.plan(classes, followed['shares'] if following else {})
    rows = shaper_map.settle(followed['rules'], plan)
    conf = None
    if not why_not:
        conf = {'owner': OWNER,
                'classes': [{'dscp': d['dscp'], 'mask': 63, 'queue': d['queue']} for d in plan['dscps']],
                'scheduling': {'*': plan['mode']} if plan['dscps'] else {},
                'limits': followed['limits'] if following else {}}
        if plan['weights'] is not None:
            conf['weights'] = plan['weights']
        if not conf['classes'] and not conf['limits']:
            conf = None
    return {'why_not': why_not, 'follow': follow, 'plan': plan, 'shaper': rows, 'conf': conf}


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
    """(status, message): what this plugin set put back, through the switch tool."""
    if not ours():
        return 'nothing', ''
    got = tool('clear')
    if got is None:
        return 'nothing', ''
    if got[0] == 0:
        return 'cleared', last(got)
    return 'failed', last(got)


def last(got):
    """The tool's last line worth saying: its refusal or failure, else what it did."""
    lines = [l.strip() for l in (got[2] or '').splitlines() if l.strip()]
    lines = lines or [l.strip() for l in (got[1] or '').splitlines() if l.strip()]
    return lines[-1] if lines else ''


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


def apply():
    root = hardware.config(CONFIG)
    if root is None:
        return {'status': 'failed', 'message': 'config.xml could not be read'}
    decided = decide(root, can())
    status, said = 'nothing', ''
    if decided['conf'] is None:
        status, said = clear()
    elif owner_of(SETTINGS) not in (None, OWNER):
        status, said = 'refused', 'the switch\'s settings file is another plugin\'s (%s): not overwritten' % owner_of(SETTINGS)
    else:
        write_settings(decided['conf'])
        got = tool('apply')
        if got is None:
            status, said = 'failed', 'os-xgs-npu\'s switch tool is not here'
        else:
            status, said = ('applied' if got[0] == 0 else 'failed'), last(got)
    keep(dict(decided, status=status, said=said, time=time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())))
    if status in ('failed', 'refused'):
        return {'status': 'failed', 'message': said}
    return {'status': 'ok', 'message': status}


def main(argv):
    if argv == ['plan']:
        root = hardware.config(CONFIG)
        print(json.dumps(decide(root, can()) if root is not None else {'error': 'config.xml could not be read'},
                         sort_keys=True))
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
