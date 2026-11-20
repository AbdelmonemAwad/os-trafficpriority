#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""apply.py, the switch's queues set from the page's Apply, run as configd runs it, against config.xml
files and the rules file of a filter reload written here, and a stand-in for os-xgs-npu's switch tool
(switch_qos.py) that says what model this is, keeps the settings file it is given and answers as it is
told. What is checked: the settings file written with this plugin's name and what hardware.py and
shaper_map.py decide from the classes the rules file holds a rule for, while it holds the one setting
every IPv4 connection's DSCP to 0, and the tool asked to apply it, "running" kept for the page while it
does; a rules file without that rule giving the switch no class's queue; a refusal or a failure of the tool said with the tool's own last line,
a tool that runs out of time or says nothing said as such; Traffic Priority off, nothing left for the
switch, a minimum beside a strict class, the XGS 136 family - what this plugin set put back, its settings
file removed before the tool is asked, and nothing of another plugin's touched or overwritten; a rule set
pf refused leaving the switch as it is; nothing at all without os-xgs-npu; clear for the plugin's
removal; and the outcome kept for the page.

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


# The switch tool: "can" answers model.json; "apply" and "clear" write down the call, what the settings
# file held then and what the page was told then, and answer with answer.json's exit, stdout and stderr,
# after its sleep; clear removes the settings file when it succeeds, as the real one does first.
TOOL = r'''import json, os, sys, time
d = os.environ['FAKE_DIR']
cmd = sys.argv[1]
if cmd == 'can':
    print(open(os.path.join(d, 'model.json')).read())
    sys.exit(0)
settings = os.environ['TP_SWITCH_SETTINGS']
held = open(settings).read() if os.path.exists(settings) else None
told = json.load(open(os.environ['TP_RESULT'])).get('status') if os.path.exists(os.environ['TP_RESULT']) else None
with open(os.path.join(d, 'calls'), 'a') as f:
    f.write(json.dumps([cmd, json.loads(held) if held else None, told]) + '\n')
answer = json.load(open(os.path.join(d, 'answer.json'))) if os.path.exists(os.path.join(d, 'answer.json')) else {}
time.sleep(answer.get('sleep', 0))
if cmd == 'clear' and os.path.exists(settings):
    os.remove(settings)
sys.stdout.write(answer.get('out', ''))
sys.stderr.write(answer.get('err', ''))
sys.exit(answer.get('rc', 0))
'''

XGS3300 = {'assembly': 'AMDA0202-0004', 'family': 'octeontx', 'writes': True, 'why': '', 'entries': 2,
           'ports': ['Port1', 'Port2'], 'devices': {'oxp2': 'Port1', 'oxp3': 'Port2'}}
XGS136 = {'assembly': 'AMDA0201-0003', 'family': 'armada', 'writes': False, 'why': 'read-only', 'entries': 2,
          'ports': [], 'devices': {}}
U = '6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a0%d'


def config(on='1', classes=(('46', ''),), follow='0', shaper=''):
    body = ''.join('<class uuid="%s"><enabled>1</enabled><sequence>%d</sequence>'
                   '<dscp>%s</dscp><minimum>%s</minimum><ipprotocol>inet</ipprotocol></class>' % (U % i, 100 + i, d, m)
                   for i, (d, m) in enumerate(classes))
    return ('<?xml version="1.0"?><opnsense><interfaces><wan><if>oxp3</if></wan></interfaces><OPNsense>'
            '<TrafficPriority><general><enabled>%s</enabled><follow_shaper>%s</follow_shaper></general><classes>%s'
            '</classes></TrafficPriority>%s</OPNsense></opnsense>' % (on, follow, body, shaper))


CLEARING = 'match in inet from {any} to {any} scrub ( set-tos 0x00 ) label "trafficpriority-clear"\n'


def rules(classes=(('46', ''),)):
    """The rules file as the hook writes it for these classes on an XGS 3300: while one has a place - a
    DSCP above Best Effort - the rule setting every IPv4 connection's DSCP to 0 first, then the classes'
    own."""
    placed = any(int(d) not in (0, 1, 8) for d, _ in classes)
    return (CLEARING if placed else '') + ''.join('match in on igb1 inet scrub ( set-tos 0x%02x ) label '
                                                  '"trafficpriority-%s"\n' % (int(d) << 2, U % i)
                                                  for i, (d, _) in enumerate(classes))


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
             'TP_RESULT': os.path.join(tmp, 'tp', 'hardware.json'), 'TP_PROJECT': os.path.join(tmp, 'XGS.xml'),
             'TP_RULES': os.path.join(tmp, 'rules.debug'), 'TP_RULES_ERROR': os.path.join(tmp, 'rules.error')}
    env = dict(os.environ, TP_PYTHON=sys.executable, FAKE_DIR=tmp, TP_SWITCH_TIMEOUT='3', **paths)

    def given(text=None, model=XGS3300, answer=None, ruled=None):
        if text is not None:
            with open(paths['TP_CONFIG'], 'w', encoding='utf-8') as handle:
                handle.write(text)
        if ruled is not None:
            with open(paths['TP_RULES'], 'w', encoding='utf-8') as handle:
                handle.write(ruled)
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
    both = (('46', ''), ('34', ''))
    given(config(classes=both), ruled=rules(both))
    check('Apply: ok, applied', run(), {'status': 'ok', 'message': 'applied'})
    want = {'owner': 'os-trafficpriority', 'classes': [{'dscp': 46, 'mask': 63, 'queue': 7},
                                                        {'dscp': 34, 'mask': 63, 'queue': 6}],
            'scheduling': {'*': 2}, 'limits': {}}
    check('the settings file: this plugin\'s, the two places of the rules file strict in 7 and 6, the ports strict '
          'for both', settings(), want)
    check('the switch tool asked to apply what the file held, once, the page told it runs meanwhile', calls(),
          [['apply', want, 'running']])
    check('the outcome kept for the page', (result()['status'], result()['why_not'], result()['conf']), ('applied', '', want))
    mins = (('46', '20'), ('34', '30'))
    given(config(classes=mins), ruled=rules(mins))
    run()
    check('minimums: all weighted, 20 and 30 turns against 50 for the rest',
          (settings()['scheduling'], settings()['weights'].count(7), settings()['weights'].count(6),
           settings()['weights'].count(0)), ({'*': 0}, 20, 30, 50))
    # the places come with the rules file: a class the last filter reload wrote no rule for has none
    given(config(classes=both), ruled=rules((('46', ''),)))
    run()
    check('the switch given only what the rules file places', settings()['classes'], [{'dscp': 46, 'mask': 63, 'queue': 7}])
    # and without the rule setting every IPv4 connection's DSCP to 0 - a filter reload before the switch
    # tool was there - no class has a queue in the switch: what was set put back
    given(config(classes=both), ruled=rules(both).replace(CLEARING, ''))
    check('a rules file without the rule setting DSCP 0: nothing for the switch, what was set put back',
          (run(), calls(), settings()), ({'status': 'ok', 'message': 'cleared'}, [['clear', None, 'running']], None))

    # the tool refuses, fails, runs out of time, says nothing
    given(config(), ruled=rules(), answer={'rc': 1, 'err': 'TCAM entry 3 is in use by something else (page 0 keys '
                                                         '0xc000 0x0000): nothing written\n'})
    check('a refusal of the tool: failed, with its own words', run(),
          {'status': 'failed', 'message': 'TCAM entry 3 is in use by something else (page 0 keys 0xc000 0x0000): nothing written'})
    check('...kept for the page', (result()['status'], result()['said'][:12]), ('failed', 'TCAM entry 3'))
    given(answer={'sleep': 6})
    check('a tool that runs out of time: said so', run(), {'status': 'failed',
                                                           'message': 'the switch tool did not finish within 3 s'})
    given(answer={'rc': 1})
    check('a tool that ends without a word: said so', run()['message'], 'the switch tool ended (exit 1) without a word')

    # a minimum beside a strict class: nothing for the switch, what was set put back, why said
    given(config(), ruled=rules())
    run()
    mixed = (('46', ''), ('34', '30'))
    given(config(classes=mixed), ruled=rules(mixed))
    check('a minimum beside a strict class: refused, what was set put back - the settings file gone before the tool '
          'was asked', (run(), calls(), settings()), ({'status': 'failed', 'message': 'mix'}, [['clear', None, 'running']], None))
    check('...the page told why', (result()['status'], result()['refused']), ('refused', 'mix'))

    # a rule set pf refused: the switch left as it is
    given(config(), ruled=rules())
    run()
    with open(paths['TP_RULES_ERROR'], 'w', encoding='utf-8') as handle:
        handle.write('There were error(s) loading the rules')
    before = settings()
    given()
    check('pf refused the last rule set: nothing asked of the switch, said', (run()['status'], calls(), settings()),
          ('failed', [], before))
    check('...kept for the page', (result()['status'], result()['refused']), ('refused', 'rules'))
    os.remove(paths['TP_RULES_ERROR'])

    # Firewall: Shaper followed
    given(config(follow='1', shaper=SHAPER), ruled=rules())
    run()
    check('Firewall: Shaper followed: a rule taking everything out of WAN limits Port2', settings()['limits'],
          {'Port2': 100000})
    given(config(follow='0', shaper=SHAPER))
    run()
    check('...not followed: no limit', settings()['limits'], {})

    # off: what this plugin set put back, the settings file removed first
    given(config(on='0'))
    check('Traffic Priority off: what it set put back, the settings file gone before the tool was asked',
          (run(), calls(), settings()), ({'status': 'ok', 'message': 'cleared'}, [['clear', None, 'running']], None))
    check('...and the page told', (result()['status'], result()['why_not'], result()['conf']), ('cleared', 'plugin-off', None))
    given()
    check('off again, nothing of its own left: the tool not asked', (run(), calls()), ({'status': 'ok', 'message': 'nothing'}, []))
    given(config(), ruled=rules())
    run()
    given(config(on='0'), answer={'rc': 1, 'err': 'not read back as written: Port5 (switch port 5) scheduling 0\n'})
    check('a put-back that fails: said, and the settings file gone all the same - nothing sets it again',
          (run()['status'], settings(), result()['status']), ('failed', None, 'failed'))

    # nothing for the switch: Best Effort alone
    given(config(classes=(('0', ''),)), ruled=rules((('0', ''),)), answer={})
    check('nothing for the switch: nothing asked of it', (run()['status'], calls()), ('ok', []))

    # the XGS 136 family: read only
    given(config(), ruled=rules(), model=XGS3300)
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

    # without os-xgs-npu: nothing at all; an os-xgs-npu without the switch tool said as such
    given(config(), ruled=rules())
    os.rename(tool, tool + '.gone')
    check('no os-xgs-npu: nothing asked, nothing written, the page told', (run()['status'], settings(),
                                                                          result()['why_not']), ('ok', None, 'no-project'))
    with open(paths['TP_PROJECT'], 'w', encoding='utf-8') as handle:
        handle.write('<model/>')
    check('an os-xgs-npu without the switch tool: said', (run()['status'], settings(), result()['why_not']),
          ('ok', None, 'no-tool'))
    os.remove(paths['TP_PROJECT'])
    os.rename(tool + '.gone', tool)

    # clear, at the plugin's removal
    given(config(), ruled=rules())
    run()
    check('clear: its own put back, the settings file gone first, the outcome gone',
          (run('clear'), calls()[-1], os.path.exists(paths['TP_RESULT'])),
          ({'status': 'ok', 'message': 'cleared'}, ['clear', None, 'applied'], False))
    given(answer={'rc': 0})
    check('clear with nothing of its own: nothing asked', (run('clear')['status'], calls()), ('ok', []))

    # plan: what Apply would set, nothing written
    given(config(classes=(('46', '25'),)), ruled=rules((('46', '25'),)))
    plan = run('plan')
    check('plan: the decision, nothing asked or written', (plan['conf']['classes'], calls(), settings()),
          ([{'dscp': 46, 'mask': 63, 'queue': 7}], [], None))
    check('usage', run('nonsense').get('rc'), 64)

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
