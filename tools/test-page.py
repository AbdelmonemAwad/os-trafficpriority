#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The page's script (index.volt), run under node with a stand-in for jQuery and OPNsense's page helpers, as
os-blocklists' tools/test-page.py runs its own - the groups and users, applications and categories above
all (2026-11-20): the Applied tab's Their tables column drawn from status.py's items - each one's table and
what pf holds in it, or why it has none - the In pf column of a class with no table on one side, the
switch queue of one that keeps its place meanwhile, the model's new refusals worded, and the lines that say
os-useridentity or os-appcontrol is not installed. Then what the dialog's help tells the owner (texts()).
The template's texts are put in as their English msgids. No OPNsense, no browser:

    python3 tools/test-page.py

node is needed (GitHub's runners have it); without it this says so and fails.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VOLT = os.path.join(ROOT, 'src', 'opnsense', 'mvc', 'app', 'views', 'OPNsense', 'TrafficPriority', 'index.volt')
FORM = os.path.join(ROOT, 'src', 'opnsense', 'mvc', 'app', 'controllers', 'OPNsense', 'TrafficPriority', 'forms',
                    'dialogClass.xml')
LANG = re.compile(r"\{\{\s*lang\._\('((?:[^'\\]|\\.)*)'\)\s*\}\}")

# jQuery, OPNsense's page helpers and the DOM, as far as the page's script uses them: elements by id, made
# from a tag, with their text, class and children, shown or hidden; what each grid and request was given
# recorded in R
HARNESS = r'''
const R = {grids: {}, gets: {}, requests: [], timers: 0};
const registry = {};
function decode(v) {
    return String(v).replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#039;/g, "'").replace(/&amp;/g, '&');
}
class El {
    constructor(tag, id) { this.tag = tag; this.id = id || null; this.cls = ''; this.attrs = {};
        this.textValue = null; this.children = []; this.shown = true; }
    getText() { return (this.textValue || '') + this.children.map(c => c.getText()).join(''); }
}
function byId(id) { if (!registry[id]) { registry[id] = new El('div', id); } return registry[id]; }
function make(html) {
    const el = new El((html.match(/^<(\w+)/) || [])[1] || 'div');
    const cls = html.match(/class="([^"]*)"/);
    if (cls) { el.cls = cls[1]; }
    return el;
}
class Q {
    constructor(els) { this.els = els; }
    each(fn) { this.els.forEach(fn); return this; }
    empty() { return this.each(e => { e.children = []; e.textValue = null; }); }
    append(x) { return this.each(e => { (x instanceof Q ? x.els : [x]).forEach(c => e.children.push(c)); }); }
    addClass(c) { return this.each(e => { e.cls = (e.cls + ' ' + c).trim(); }); }
    hasClass(c) { return this.els.some(e => (' ' + e.cls + ' ').indexOf(' ' + c + ' ') >= 0); }
    attr(name) { return this.els.length ? this.els[0].attrs[name] : undefined; }
    text(v) {
        if (v === undefined) { return this.els.map(e => e.getText()).join(''); }
        return this.each(e => { e.textValue = String(v); e.children = []; });
    }
    html(v) {
        if (v === undefined) { return this.els.length ? this.els[0].textValue : ''; }
        return this.each(e => { e.textValue = decode(v); e.children = []; });
    }
    toggle(show) { return this.each(e => { e.shown = show === undefined ? !e.shown : !!show; }); }
    show() { return this.toggle(true); }
    hide() { return this.toggle(false); }
    click(fn) { return this.on('click', fn); }
    on() { return this; }
    tab() { return this; }
    selectpicker() { return this; }
    replaceInputWithSelector() { return this; }
    bootgrid() { return this.each(e => { R.requests.push('reload ' + e.id); }); }
    UIBootgrid(options) { return this.each(e => { R.grids[e.id] = options; }); }
    SimpleActionButton(options) { R.apply = options; return this; }
}
function $(x) {
    if (x instanceof El) { return new Q([x]); }
    if (x === document) { return {ready: fn => fn()}; }
    if (typeof x === 'string' && /^#[\w-]+$/.test(x)) { return new Q([byId(x.slice(1))]); }
    if (typeof x === 'string' && x[0] === '#') { return new Q(x.split(/,\s*/).map(s => byId(s.slice(1)))); }
    if (typeof x === 'string' && x[0] === '<') { return new Q([make(x)]); }
    return new Q([]);
}
$.each = function (list, fn) { (list || []).forEach((v, i) => fn(i, v)); };
const document = {};
const window = {location: {hash: ''}};
const history = {pushState() {}};
function setTimeout() { R.timers++; return R.timers; }
function clearTimeout() {}
function ajaxGet(url, data, cb) { R.requests.push('get ' + url); R.gets[url] = cb; }
function mapDataToFormUI(map) { R.forms = map; return {done: fn => fn()}; }
function saveFormToEndpoint(url, form, cb) { R.requests.push('save ' + form); cb(); }
'''

TESTS = r'''
const out = {};
const f = R.grids['grid-applied'].options.formatters;
const alice = {kind: 'user', key: 'u', name: 'alice', table: 'uid_alice', why: '', count: 1};
const staff = {kind: 'group', key: 'g', name: 'Staff', table: 'uid_staff', why: '', count: 1234};
const zoom = {kind: 'application', key: 'Zoom', name: 'Zoom', table: 'appcontrol_Zoom', why: '', count: null};
const netflix = {kind: 'application', key: 'Netflix', name: 'Netflix', table: '', why: 'no-table', count: null};
const voip = {kind: 'category', key: 'VoIP', name: 'VoIP', table: '', why: 'appcontrol-off', count: null};
const odd = {kind: 'user', key: 'x', name: 'x', table: '', why: 'something new', count: null};
out.tables = f.tables({id: 'tables'}, {tables: [alice, staff, zoom, netflix, voip, odd]});
out.tablesNone = f.tables({id: 'tables'}, {tables: []});
out.tablesMissing = f.tables({id: 'tables'}, {});
out.inpfUsers = f.inpf({id: 'rules'}, {enabled: true, problem: '', idle: 'users', rules: 0});
out.inpfApps = f.inpf({id: 'rules'}, {enabled: true, problem: '', idle: 'apps', rules: 0});
out.inpfProblem = f.inpf({id: 'rules'}, {enabled: true, problem: 'sources', idle: 'users', rules: 0});
out.inpfProblems = ['users', 'application', 'destinations'].map(p => f.inpf({id: 'rules'}, {enabled: true, problem: p, rules: 0}));
out.inpfHeld = f.inpf({id: 'rules'}, {enabled: true, problem: '', idle: '', rules: 2});
/* the review's PG1: pf holds the class's rules from the last reload, and config.xml as saved since makes none */
out.inpfHeldIdle = f.inpf({id: 'rules'}, {enabled: true, problem: '', idle: 'users', rules: 3, written: 3, states: 12});
out.inpfHeldProblem = f.inpf({id: 'rules'}, {enabled: true, problem: 'sources', idle: 'users', rules: 2, written: 2});
out.inpfHeldApps = f.inpf({id: 'rules'}, {enabled: true, problem: '', idle: 'apps', rules: 4, written: 4, not_placed: 1});
out.inpfWrittenIdle = f.inpf({id: 'rules'}, {enabled: true, problem: '', idle: 'users', rules: 0, written: 2});
out.queueIdle = f.queue({id: 'queue'}, {switch_not: '', switch: {why: 'hardware', kind: 'strict', queue: 7, idle: true}});
out.queueHeld = f.queue({id: 'queue'}, {switch_not: '', switch: {why: 'hardware', kind: 'strict', queue: 7, idle: false}});
const draw = R.gets['/api/trafficpriority/service/status'];
const base = {enabled: true, pf: true, refused: false, marked: 0, project: true, writes_mark: true,
              classes: [], hardware: {why_not: 'no-project', dscps: [], classes: {}, last: null}};
const copy = v => JSON.parse(JSON.stringify(v));
let s = copy(base);
s.others = {identity: false, appcontrol: true};
draw(s);
out.missingIdentity = {identity: byId('tp-no-identity').shown, appcontrol: byId('tp-no-appcontrol').shown};
s.others = {identity: true, appcontrol: false};
draw(s);
out.missingApps = {identity: byId('tp-no-identity').shown, appcontrol: byId('tp-no-appcontrol').shown};
s = copy(base);
draw(s);
out.noOthers = {identity: byId('tp-no-identity').shown, appcontrol: byId('tp-no-appcontrol').shown};
console.log(JSON.stringify(out));
'''

FAILED = []
CHECKS = [0]


def check(ok, what):
    CHECKS[0] += 1
    if not ok:
        FAILED.append(what)
        print('FAIL ' + what)


def script():
    text = open(VOLT, encoding='utf-8').read()
    body = text.split('<script>', 1)[1].split('</script>', 1)[0]
    # a msgid inside the page's double-quoted strings, as Volt writes it there: its English, JS-escaped
    body = LANG.sub(lambda m: json.dumps(m.group(1).replace("\\'", "'"))[1:-1], body)
    body = body.replace("{{ formGridClass['table_id'] }}", 'grid-class')
    body = re.sub(r'\{#.*?#\}', '', body, flags=re.S)
    if '{{' in body or '{%' in body:
        raise ValueError('a template expression is left in the script')
    return body


def plain(html):
    return re.sub(r'<[^>]+>', '', html)


def texts():
    """What the dialog's help tells the owner of the tables: the limits the design settled, said where he
    chooses them."""
    form = open(FORM, encoding='utf-8').read()
    volt = ' '.join(m.group(1) for m in LANG.finditer(open(VOLT, encoding='utf-8').read()))
    check('take the place of Source' in form and 'take the place of Destination' in form,
          'texts (help): groups and users take the place of Source, applications that of Destination')
    check("os-xgs-npu's cut list holds User Identity's tables" in form and 'keeps the mark it opened with' in form,
          'texts (help): a connection keeps its mark; the cut list where os-xgs-npu has it')
    check('10 to 70 seconds' in form and 'Expire' in form and 'A server two applications share is in both tables' in form,
          'texts (help): when nDPI names a connection, how long a server stays, servers shared')
    check('give such a class a minimum' in form and 'a whole port' in form,
          'texts (help): a device naming its own server - a class without a minimum can take a whole port')
    check('makes no rule at all' in form and 'makes no rule' in volt and 'keeps its switch queue' in volt,
          'texts: a class with no table makes no rule, and on an XGS 3300 keeps its queue')
    template = open(VOLT, encoding='utf-8').read()
    check('id="tp-no-identity"' in template and 'User Identity (os-useridentity) is not installed' in volt and
          'id="tp-no-appcontrol"' in template and 'Application Control (os-appcontrol) is not installed' in volt,
          'texts (Classes): the lines the page shows when either plugin is not installed')


def main():
    node = shutil.which('node')
    if node is None:
        print('node is not installed: the page\'s script cannot be run here')
        return 1
    tmp = tempfile.mkdtemp(prefix='trafficpriority-page-')
    try:
        path = os.path.join(tmp, 'page.js')
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(HARNESS + script() + TESTS)
        run = subprocess.run([node, path], capture_output=True, text=True, encoding='utf-8', timeout=60)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if run.returncode != 0:
        print('FAIL the page\'s script under node:\n' + run.stderr[-3000:])
        return 1
    out = json.loads(run.stdout.strip().splitlines()[-1])
    lines = [plain(x) for x in out['tables'].split('<br/>')]
    check(lines == ['alice (a user): uid_alice (addresses in it now: 1)',
                    'Staff (a group): uid_staff (addresses in it now: 1,234)',
                    'Zoom (an application): appcontrol_Zoom',
                    'Netflix (an application): no table: not applied in its plugin yet - or, an application, not chosen '
                    'there for a table',
                    'VoIP (a category): Application Control is not classifying',
                    'x (a user): something new'],
          'Their tables: each item with its kind, its table and what pf holds in it - none counted when not asked - or '
          'why it has none, a reason the page does not know shown as given: %r' % (lines,))
    check('text-warning' in out['tables'].split('<br/>')[3] and 'text-warning' not in out['tables'].split('<br/>')[0],
          'Their tables: an item with no table marked as a warning, one with a table not')
    check(plain(out['tablesNone']) == '-' and plain(out['tablesMissing']) == '-', 'Their tables: none - a dash')
    check(plain(out['inpfUsers']) == 'no rule: none of its groups and users has a table now' and
          plain(out['inpfApps']) == 'no rule: none of its applications and categories has a table now',
          'In pf: a class with no table on one side - which: %r %r' % (out['inpfUsers'], out['inpfApps']))
    check(plain(out['inpfProblem']) == 'no rule: groups and users beside a source',
          'In pf: a problem of the class before its tables: %r' % (out['inpfProblem'],))
    check([plain(x) for x in out['inpfProblems']] == ['no rule: groups and users field not readable',
                                                      'no rule: application or category field not readable',
                                                      'no rule: applications or categories beside a destination'],
          'In pf: the new refusals worded: %r' % (out['inpfProblems'],))
    check(plain(out['inpfHeld']) == '2 rules', 'In pf: a class held, its rules counted')
    check(plain(out['inpfHeldIdle']) == '3 rules · the next filter reload writes none: none of its groups and users has a '
          'table now', 'In pf: what pf holds first, then that the next filter reload writes none, and why: %r' %
          (out['inpfHeldIdle'],))
    check(plain(out['inpfHeldProblem']) == '2 rules · the next filter reload writes none: groups and users beside a source'
          and plain(out['inpfHeldApps']) == '4 rules · 1 not placed · the next filter reload writes none: none of its '
          'applications and categories has a table now',
          'In pf: the same for a problem, and for applications with a rule not placed: %r %r' %
          (out['inpfHeldProblem'], out['inpfHeldApps']))
    check('text-warning' not in out['inpfHeldIdle'].split(' · ')[0] and 'text-warning' in out['inpfHeldIdle'].split(' · ')[1],
          'In pf: the rules pf holds plain, the next reload\'s none a warning')
    check(plain(out['inpfWrittenIdle']) == 'no rule: none of its groups and users has a table now',
          'In pf: no rule in pf, none written next either - the reason alone: %r' % (out['inpfWrittenIdle'],))
    check(plain(out['queueIdle']) == 'queue 7, strict · kept while it has no table: it marks nothing meanwhile' and
          plain(out['queueHeld']) == 'queue 7, strict',
          'Switch queue: a class with no table keeps its queue, said; one with them, as before: %r' % (out['queueIdle'],))
    check(out['missingIdentity'] == {'identity': True, 'appcontrol': False},
          'Classes: User Identity not installed - its line shown, Application Control\'s hidden: %r' % (out['missingIdentity'],))
    check(out['missingApps'] == {'identity': False, 'appcontrol': True}, 'Classes: Application Control not installed - said')
    check(out['noOthers'] == {'identity': False, 'appcontrol': False},
          'Classes: a status without them (an older status script) - neither line shown')
    texts()
    print('%d of %d checks failed' % (len(FAILED), CHECKS[0]) if FAILED else '%d checks passed' % CHECKS[0])
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
