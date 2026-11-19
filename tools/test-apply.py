#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""apply.py, the switch's queues set from the page's Apply, run as configd runs it, against config.xml
files written here and a stand-in for os-xgs-npu's switch tool (switch_qos.py) that says what model
this is, keeps the settings file it is given and answers as it is told. What is checked: the settings
file written with this plugin's name and what hardware.py and shaper_map.py decide, and the tool asked
to apply it; a refusal or a failure of the tool said on the page's terms, with the tool's own last
line; Traffic Priority off, nothing left for the switch, the XGS 136 family - what this plugin set put
back, and nothing of another plugin's touched or overwritten; nothing at all without os-xgs-npu;
clear for the plugin's removal; and the outcome kept for the page.

    python3 tools/test-apply.py"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APPLY = os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'trafficpriority', 'apply.py')

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


# The switch tool: "can" answers model.json; "apply" and "clear" write down the call and what the
# settings file held, and answer with answer.json's exit, stdout and stderr; clear removes the settings
# file when it succeeds, as the real one does.
TOOL = r'''import json, os, sys
d = os.environ['FAKE_DIR']
cmd = sys.argv[1]
if cmd == 'can':
    print(open(os.path.join(d, 'model.json')).read())
    sys.exit(0)
settings = os.environ['TP_SWITCH_SETTINGS']
held = open(settings).read() if os.path.exists(settings) else None
with open(os.path.join(d, 'calls'), 'a') as f:
    f.write(json.dumps([cmd, json.loads(held) if held else None]) + '\n')
answer = json.load(open(os.path.join(d, 'answer.json'))) if os.path.exists(os.path.join(d, 'answer.json')) else {}
if cmd == 'clear' and answer.get('rc', 0) == 0 and os.path.exists(settings):
    os.remove(settings)
sys.stdout.write(answer.get('out', ''))
sys.stderr.write(answer.get('err', ''))
sys.exit(answer.get('rc', 0))
'''

XGS3300 = {'family': 'octeontx', 'writes': True, 'why': '', 'entries': 2, 'ports': ['Port1', 'Port2'],
           'devices': {'oxp2': 'Port1', 'oxp3': 'Port2'}}
XGS136 = {'family': 'armada', 'writes': False, 'why': 'read-only', 'entries': 2, 'ports': [], 'devices': {}}


def config(on='1', classes=(('46', ''),), follow='0', shaper=''):
    body = ''.join('<class uuid="6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a0%d"><enabled>1</enabled><sequence>%d</sequence>'
                   '<dscp>%s</dscp><minimum>%s</minimum><ipprotocol>inet</ipprotocol></class>' % (i, 100 + i, d, m)
                   for i, (d, m) in enumerate(classes))
    return ('<?xml version="1.0"?><opnsense><interfaces><wan><if>oxp3</if></wan></interfaces><OPNsense>'
            '<TrafficPriority><general><enabled>%s</enabled><follow_shaper>%s</follow_shaper></general><classes>%s'
            '</classes></TrafficPriority>%s</OPNsense></opnsense>' % (on, follow, body, shaper))


SHAPER = ('<TrafficShaper><pipes><pipe uuid="p1"><enabled>1</enabled><bandwidth>100</bandwidth>'
          '<bandwidthMetric>Mbit</bandwidthMetric><mask>none</mask><description>Up</description></pipe></pipes>'
          '<queues/><rules><rule uuid="r1"><enabled>1</enabled><sequence>1</sequence><interface>wan</interface>'
          '<proto>ip</proto><source>any</source><destination>any</destination><src_port>any</src_port>'
          '<dst_port>any</dst_port><direction>out</direction><target>p1</target><description>All up</description>'
          '</rule></rules></TrafficShaper>')

with tempfile.TemporaryDirectory() as tmp:
    tool = os.path.join(tmp, 'switch_qos.py')
    with open(tool, 'w', encoding='utf-8') as handle:
        handle.write(TOOL)
    paths = {'TP_CONFIG': os.path.join(tmp, 'config.xml'), 'TP_SWITCH_TOOL': tool,
             'TP_SWITCH_SETTINGS': os.path.join(tmp, 'db', 'switch-qos.json'),
             'TP_SWITCH_STATE': os.path.join(tmp, 'db', 'switch-qos.state'),
             'TP_RESULT': os.path.join(tmp, 'tp', 'hardware.json')}
    env = dict(os.environ, TP_PYTHON=sys.executable, FAKE_DIR=tmp, **paths)

    def given(text=None, model=XGS3300, answer=None):
        if text is not None:
            with open(paths['TP_CONFIG'], 'w', encoding='utf-8') as handle:
                handle.write(text)
        with open(os.path.join(tmp, 'model.json'), 'w', encoding='utf-8') as handle:
            handle.write(json.dumps(model))
        a = os.path.join(tmp, 'answer.json')
        if answer is None:
            if os.path.exists(a):
                os.remove(a)
        else:
            with open(a, 'w', encoding='utf-8') as handle:
                json.dump(answer, handle)
        if os.path.exists(os.path.join(tmp, 'calls')):
            os.remove(os.path.join(tmp, 'calls'))

    def run(*args):
        done = subprocess.run([sys.executable, APPLY] + list(args), env=env, capture_output=True, text=True, timeout=120)
        try:
            return json.loads(done.stdout)
        except ValueError:
            return {'stdout': done.stdout, 'stderr': done.stderr, 'rc': done.returncode}

    def calls():
        try:
            with open(os.path.join(tmp, 'calls'), encoding='utf-8') as handle:
                return [json.loads(line) for line in handle]
        except OSError:
            return []

    def settings():
        try:
            with open(paths['TP_SWITCH_SETTINGS'], encoding='utf-8') as handle:
                return json.load(handle)
        except OSError:
            return None

    def result():
        with open(paths['TP_RESULT'], encoding='utf-8') as handle:
            return json.load(handle)

    # set
    given(config(classes=(('46', ''), ('34', '30'))))
    check('Apply: ok, applied', run(), {'status': 'ok', 'message': 'applied'})
    want = {'owner': 'os-trafficpriority', 'classes': [{'dscp': 46, 'mask': 63, 'queue': 7},
                                                        {'dscp': 34, 'mask': 63, 'queue': 6}],
            'scheduling': {'*': 1}, 'limits': {}}
    got = settings()
    check('the settings file: this plugin\'s, EF strict in 7, AF41 weighted in 6, the ports strict for 7',
          {k: v for k, v in got.items() if k != 'weights'}, want)
    check('the settings file: 30 turns of AF41\'s queue against 70 for the rest',
          (got['weights'].count(6), got['weights'].count(0)), (30, 70))
    check('the switch tool asked to apply what the file held, once', calls(), [['apply', got]])
    check('the outcome kept for the page', (result()['status'], result()['why_not'], result()['conf']), ('applied', '', got))

    # the tool refuses or fails
    given(answer={'rc': 1, 'err': 'TCAM entry 3 is in use by something else (page 0 keys 0xc000 0x0000): nothing written\n'})
    check('a refusal of the tool: failed, with its own words', run(),
          {'status': 'failed', 'message': 'TCAM entry 3 is in use by something else (page 0 keys 0xc000 0x0000): nothing written'})
    check('...kept for the page', (result()['status'], result()['said'][:12]), ('failed', 'TCAM entry 3'))

    # Firewall: Shaper followed
    given(config(follow='1', shaper=SHAPER))
    run()
    check('Firewall: Shaper followed: a rule taking everything out of WAN limits Port2', settings()['limits'],
          {'Port2': 100000})
    given(config(follow='0', shaper=SHAPER))
    run()
    check('...not followed: no limit', settings()['limits'], {})

    # off: what this plugin set put back
    given(config(on='0'))
    check('Traffic Priority off: what it set put back', (run(), [c[0] for c in calls()], settings()),
          ({'status': 'ok', 'message': 'cleared'}, ['clear'], None))
    check('...and the page told', (result()['status'], result()['why_not'], result()['conf']), ('cleared', 'plugin-off', None))
    given()
    check('off again, nothing of its own left: the tool not asked', (run(), calls()), ({'status': 'ok', 'message': 'nothing'}, []))

    # nothing for the switch: Best Effort alone
    given(config(classes=(('0', ''),)))
    check('nothing for the switch: nothing asked of it', (run()['status'], calls()), ('ok', []))

    # the XGS 136 family: read only
    given(config(), model=XGS3300)
    run()
    given(model=XGS136)
    check('the XGS 136 family: what this plugin set elsewhere put back, nothing written',
          ([c[0] for c in calls()] if run() else None, settings(), result()['why_not']), (['clear'], None, 'read-only'))

    # another plugin's settings: neither overwritten nor cleared
    os.makedirs(os.path.dirname(paths['TP_SWITCH_SETTINGS']), exist_ok=True)
    other = {'owner': 'os-something', 'classes': [{'dscp': 10, 'mask': 63, 'queue': 3}]}
    with open(paths['TP_SWITCH_SETTINGS'], 'w', encoding='utf-8') as handle:
        json.dump(other, handle)
    given(model=XGS3300)
    got = run()
    check('another plugin\'s settings file: not overwritten, said', (got['status'], 'another plugin' in got['message'],
                                                                     settings(), calls()), ('failed', True, other, []))
    given(config(on='0'))
    check('...nor cleared with Traffic Priority off', (run()['status'], calls(), settings()), ('ok', [], other))
    os.remove(paths['TP_SWITCH_SETTINGS'])

    # without os-xgs-npu: nothing at all
    given(config())
    os.rename(tool, tool + '.gone')
    check('no os-xgs-npu: nothing asked, nothing written, the page told', (run()['status'], settings(),
                                                                          result()['why_not']), ('ok', None, 'no-project'))
    os.rename(tool + '.gone', tool)

    # clear, at the plugin's removal
    given(config())
    run()
    check('clear: its own put back, the outcome gone', (run('clear'), [c[0] for c in calls()][-1],
                                                        os.path.exists(paths['TP_RESULT'])),
          ({'status': 'ok', 'message': 'cleared'}, 'clear', False))
    given(answer={'rc': 0})
    check('clear with nothing of its own: nothing asked', (run('clear')['status'], calls()), ('ok', []))

    # plan: what Apply would set, nothing written
    given(config(classes=(('46', '25'),)))
    plan = run('plan')
    check('plan: the decision, nothing asked or written', (plan['conf']['classes'], calls(), settings()),
          ([{'dscp': 46, 'mask': 63, 'queue': 7}], [], None))
    check('usage', run('nonsense').get('rc'), 64)

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
