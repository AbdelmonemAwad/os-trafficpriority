#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""
What the page shows, as one JSON object: whether Traffic Priority is on and, for each class, what pf was
given for it at the last filter reload (/tmp/rules.debug) and what pf holds now (pfctl -v -s rules) -
its rules, found by their label, and what pf counted for them since that reload; whether pf refused
the rule set of that reload; how many connections pf holds now with a mark set coming in, each once,
while a class marks (pfctl -v -s states, which shows that a mark is set, not which one); whether
os-xgs-npu is installed, whose drivers carry a connection's mark into hardware; and the switch's
queues on an XGS appliance - what Apply gives the switch for the settings as they are now
(apply.py's decision: each class's place, each rule of Firewall: Shaper with what the switch takes of
it and what stays with the host), what the last Apply did, and whether the settings changed since.
And for each class's groups and users, applications and categories (sources.py), its table or why it
has none, and how many addresses pf holds in the table now (pfctl -vv -s Tables, once) - and whether
os-useridentity and os-appcontrol are installed at all.

    status.py

Read only: the switch itself is not read (os-xgs-npu's switch_qos.py show reads it, by hand), nor is
anything of the other plugins' written.
"""

import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apply  # noqa: E402
import sources  # noqa: E402

CONFIG = '/conf/config.xml'
PFCTL = '/sbin/pfctl'
RULES = '/tmp/rules.debug'          # the rules the last filter reload gave pf (OPNsense's filter.inc)
ERRORS = '/tmp/rules.error'         # why pf refused them, when it did (filter.inc:399-437)
LABEL = 'trafficpriority-'          # Marking::LABEL, followed by the class's UUID
LABELED = re.compile(r'label "' + LABEL + r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"')
# The counters pfctl -v prints under each rule (pfctl.c:1141-1161 in FreeBSD 15.1): packets and bytes
# both ways, the states made with the rule among their match rules that are open now (States), and
# all it made since the rule was loaded (State Creations) - for a match rule pf counts the states it
# matched (pf.c's STATE_INC_COUNTERS). A filter reload loads new rules, whose counters start at 0:
# only evaluations, packets and bytes are carried over, with keepcounters only (pf_ioctl.c:1553-1574).
COUNTERS = re.compile(r'^\s+\[ Evaluations: (\d+)\s+Packets: (\d+)\s+Bytes: (\d+)\s+States: (\d+)\s*\]')
CREATED = re.compile(r'^\s+\[ Inserted: .*State Creations: (\d+)\s*\]')
# pfctl -v -s states prints a line for each state - its interface, protocol and addresses, "<-" for
# one made coming in, "->" going out - and one beneath it with what pf does to its packets
# (pf_print_state.c:226-280, 342-402 in FreeBSD 15.1). For a state pf marks it prints ", set-tos",
# but not the state's mark: pfctl reads the states through libpfctl over netlink, whose state export
# carries the state's flags, PFSTATE_SETTOS among them, and not the TOS byte the mark sets
# (pf_nl.c:148-230, the flags at 190); libpfctl leaves that byte at 0, so every marked state is
# printed ", set-tos 0x00" (pf_print_state.c:382-383). Only the ioctl and pfsync exports carry it
# (pf_ioctl.c:5931, 5965, 6105). Nor does pf keep a note of which rules a state matched - only what
# they set on it, a normalization rule's mark too (pf.c:6288).
MARKED = re.compile(r', set-tos 0x[0-9a-f]{2}\b')
# pfctl -vv -s Tables: a table's line - its flags (c p a i r h C, or -), a tab, its name - and its count
TABLE_HEAD = re.compile(r'^[-cpairhC]{7}\t(\S+)$')
TABLE_ADDRESSES = re.compile(r'^\tAddresses:\s+(\d+)\s*$')
# os-xgs-npu's model: where it is installed, its drivers give a connection in hardware its pf mark
PROJECT = '/usr/local/opnsense/mvc/app/models/OPNsense/XGS/XGS.xml'


def settings(path=None, installed=None):
    """(on, [each class's uuid, whether it is switched on, its description, its DSCP, and its groups and
    users, applications and categories - each with its table or why it has none (sources.resolve()'s
    items) - and idle, the side with no table now: '', 'users' or 'apps', '' while Traffic Priority is
    off - what the next filter reload finds, not what pf holds]); None when config.xml cannot be read.
    installed: whether os-useridentity and os-appcontrol are (sources.installed()'s answer), read from their
    model files when not given."""
    try:
        root = ET.parse(path or CONFIG).getroot()
    except (OSError, ET.ParseError):
        return None
    own = root.find('OPNsense/TrafficPriority')
    if own is None:
        return False, []
    on = (own.findtext('general/enabled') or '0') == '1'
    found_aliases, found_rows = sources.aliases(root), sources.rows(root)
    found_plugins = sources.plugins(root, installed)
    classes = []
    for node in own.findall('classes/class'):
        resolved = sources.resolve({child.tag: (child.text or '') for child in node}, found_aliases, found_rows,
                                   found_plugins)
        classes.append({
            'uuid': (node.get('uuid') or '').lower(),
            'enabled': (node.findtext('enabled') or '1') == '1',
            'description': node.findtext('description') or '',
            'dscp': (node.findtext('dscp') or '').strip(),
            'tables': resolved['items'],
            # the side the next filter reload finds no table for, as config.xml is now; none while Traffic
            # Priority is off, when that reload writes no class's rule at all
            'idle': sources.idle_side(resolved) if on else '',
        })
    return on, classes


def pf_table(name):
    """How many addresses pf holds in a table now (pfctl -t <table> -T show); None when pf holds no such
    table or could not be asked."""
    try:
        done = subprocess.run([PFCTL, '-t', name, '-T', 'show'], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    return len([line for line in done.stdout.splitlines() if line.strip()])


def pf_tables(text):
    """{table: how many addresses pf holds in it} from pfctl -vv -s Tables, which prints each active table of
    the main ruleset as its seven flags, a tab and its name, then its counters, the first "\\tAddresses:" and
    the number (pfctl_table.c's print_table() and print_tstats(), read in FreeBSD's main branch of
    2026-11-16; not yet run on 15.1) - every table's count in one call, where -T show prints every address
    of each to count it. A table in an anchor (name@anchor) is not one of the aliases' and is left out;
    None when nothing could be read."""
    if text is None:
        return None
    out = {}
    current = None
    for line in text.splitlines():
        head = TABLE_HEAD.match(line)
        if head:
            current = None if '@' in head.group(1) else head.group(1)
            continue
        found = TABLE_ADDRESSES.match(line)
        if found and current is not None:
            out[current] = int(found.group(1))
            current = None
    return out


def table_counter(run=None):
    """A table's name -> how many addresses pf holds in it now, or None when pf holds no such table: every
    table's count from one pfctl -vv -s Tables, asked the first time a count is wanted; when that answer
    cannot be read, each table asked by pfctl -t <table> -T show (pf_table()). run: what gives pfctl's
    answer, for the tests."""
    known = {}

    def count(name):
        if 'tables' not in known:
            known['tables'] = pf_tables((run or pf_tables_text)())
        if not known['tables']:
            return pf_table(name)
        return known['tables'].get(name)
    return count


def pf_tables_text():
    """pfctl -vv -s Tables, or None when pf could not be asked."""
    try:
        done = subprocess.run([PFCTL, '-vv', '-s', 'Tables'], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def tos(dscp):
    """The TOS byte pf sets for a DSCP, as pfctl prints it (Marking::tos()); None for anything that is
    not one of 0 to 63."""
    if not re.fullmatch(r'[0-9]{1,2}', dscp or '') or int(dscp) > 63:
        return None
    return '0x%02x' % (int(dscp) << 2)


def written(path=None):
    """Each class's rules in the file the last filter reload loaded, by label: those written, and those
    OPNsense wrote commented out because it could not place them - an interface that is not there, an
    address or a port it could not map."""
    out = {}
    try:
        with open(path or RULES, encoding='utf-8', errors='replace') as handle:
            for line in handle:
                found = LABELED.search(line)
                if not found:
                    continue
                entry = out.setdefault(found.group(1), {'written': 0, 'not_placed': 0})
                entry['not_placed' if line.lstrip().startswith('#') else 'written'] += 1
    except OSError:
        return None
    return out


def loaded(text):
    """Each class's rules in pf now, by label, from pfctl -v -s rules: how many, and their counters
    added up."""
    out = {}
    current = None
    for line in (text or '').splitlines():
        if not line[:1].isspace():
            found = LABELED.search(line)
            current = None
            if found:
                current = out.setdefault(found.group(1), {'rules': 0, 'packets': 0, 'bytes': 0, 'states': 0,
                                                          'created': 0})
                current['rules'] += 1
            continue
        if current is None:
            continue
        found = COUNTERS.match(line)
        if found:
            current['packets'] += int(found.group(2))
            current['bytes'] += int(found.group(3))
            current['states'] += int(found.group(4))
            continue
        found = CREATED.match(line)
        if found:
            current['created'] += int(found.group(1))
    return out


def marked(text, marks):
    """How many connections pf holds now with a mark set coming in, each once, while a class marks -
    from pfctl -v -s states: the states made coming in that pfctl shows with ", set-tos". pfctl shows
    that a mark is set, not which one: the state export it reads carries the flag and not the value
    (pf_nl.c:148-230; libpfctl leaves the value at 0), so the classes' marks cannot be told apart from
    one another, nor from the owner's - a normalization rule setting any mark on connections coming in
    is counted too. A class's rules mark the state a connection makes where it comes in (match in);
    the state it makes going out carries no mark of theirs, so a connection is counted once, however
    many classes matched it, and whenever it opened - a filter reload leaves states and their marks as
    they are. marks are those of the classes pf holds rules for: with none, no class marks, and the
    count is 0. None when pf could not be asked."""
    if text is None:
        return None
    if not marks:
        return 0
    count = 0
    inbound = False
    for line in text.splitlines():
        if not line[:1].isspace():
            inbound = ' <- ' in line
            continue
        if inbound and MARKED.search(line):
            count += 1
            inbound = False
    return count


def refused(rules=None, errors=None):
    """Whether pf refused the rule set the last filter reload wrote. OPNsense then loads the one before
    it again and writes why into /tmp/rules.error, after it wrote /tmp/rules.debug (filter.inc:399-437).
    That file stays until the firewall's status message is dismissed (FirewallStatus.php), so it counts
    only when it is not older than the rules file."""
    try:
        return os.stat(errors or ERRORS).st_mtime_ns >= os.stat(rules or RULES).st_mtime_ns
    except OSError:
        return False


def pf_show(what):
    """pfctl -v -s <what>, or None when pf could not be asked."""
    try:
        done = subprocess.run([PFCTL, '-v', '-s', what], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def switch(config, model, result, rules=None, check=None):
    """The switch's queues for the page: what Apply gives the switch now (apply.decide(), from the rules
    file of the last filter reload), what the last Apply did (its result file) - shown whatever else is
    said: a put-back or a set that failed, a refusal, a run still going - and whether the two differ,
    pending. model is what os-xgs-npu's switch tool says of this appliance (apply.can()), None without
    it. check, when given, is the switch tool's "check": whether entries 3 and 255, port 0's TCAM mode and
    its pause still hold what Apply set - the coprocessor's network agent shares the TCAM's engine."""
    decided = apply.decide(ET.parse(config or CONFIG).getroot(), model, apply.rules_text(rules))
    try:
        with open(result or apply.RESULT, encoding='utf-8') as handle:
            last = json.load(handle)
        if not isinstance(last, dict):
            last = None
    except (OSError, ValueError):
        last = None
    plan = decided['plan']
    return {
        'why_not': decided['why_not'],
        'refused': decided['refused'],
        'follow': decided['follow'],
        'classes': plan['classes'],
        'dscps': plan['dscps'],
        'mode': plan['mode'],
        'limits': (decided['conf'] or {}).get('limits', {}),
        'shaper': decided['shaper'],
        'last': {k: last.get(k) for k in ('status', 'said', 'time', 'refused')} if last else None,
        'pending': (last or {}).get('status') != 'running' and (last or {}).get('conf') != decided['conf'],
        'check': check,
    }


def check_switch():
    """The switch tool's check, as JSON; None when it cannot be asked."""
    got = apply.tool('check', '--json', timeout=90)
    if got is None:
        return None
    try:
        out = json.loads(got[1])
    except ValueError:
        return {'ok': False, 'changed': [], 'error': apply.last(got)}
    return out if isinstance(out, dict) else None


def status(config=None, rules=None, pf_text=None, project=None, states=None, errors=None, model=None, result=None,
           check=None, counts=None, installed=None):
    """counts: a table's name -> how many addresses pf holds in it (table_counter()); installed: whether
    os-useridentity and os-appcontrol are, {'identity', 'appcontrol'} - from their models' files when not
    given - which both the lines of the Classes tab and each item's reason follow."""
    installed = sources.installed() if installed is None else installed
    read = settings(config, installed)
    tables_now = keeps(config)
    if read is None:
        return {'error': 'config.xml could not be read'}
    on, classes = read
    lines = written(rules)
    held = loaded(pf_text)
    counts = counts or table_counter()
    counted = {}
    for entry in classes:
        entry.update({'written': 0, 'not_placed': 0, 'rules': 0, 'packets': 0, 'bytes': 0, 'states': 0,
                      'created': 0})
        entry.update((lines or {}).get(entry['uuid'], {}))
        entry.update(held.get(entry['uuid'], {}))
        # what each table of the class holds now, each table asked once - only while the class is on
        for item in entry['tables']:
            item['count'] = None
            if item['table'] and entry['enabled'] and on:
                if item['table'] not in counted:
                    counted[item['table']] = counts(item['table'])
                item['count'] = counted[item['table']]
    # the marks of the classes pf holds rules for: whether one of them marks at all is what counts, as
    # pfctl does not show which mark a state has (MARKED)
    marks = {tos(entry['dscp']) for entry in classes if entry['rules']} - {None}
    return {
        'enabled': on,
        'classes': classes,
        'rules_file': lines is not None,
        'pf': pf_text is not None,
        'refused': refused(rules, errors),
        'marked': marked(states, marks),
        'project': os.path.exists(project or PROJECT),
        'hardware': switch(config, model, result, rules, check),
        # whether each plugin is installed, and how many tables Application Control keeps now: none while it
        # does not classify or has not been applied yet, when the dialog has nothing of it to offer
        'others': dict(installed, appcontrol_tables=tables_now),
    }


def keeps(path=None):
    """How many tables Application Control keeps now - its aliases of applications and categories in
    Firewall: Aliases, switched on or off (sources.app_tables()); 0 when config.xml cannot be read."""
    try:
        root = ET.parse(path or CONFIG).getroot()
    except (OSError, ET.ParseError):
        return 0
    found = sources.aliases(root)
    return len(sources.app_tables(found, 'application')) + len(sources.app_tables(found, 'category'))


def main(argv):
    """status.py [check]: with check, the switch is read too - a few reads of the switch tool's, made only
    when the last Apply set it - for the page's cards; the grids ask without."""
    model = apply.can()
    checked = None
    if argv == ['check'] and model is not None and model.get('writes'):
        try:
            with open(apply.RESULT, encoding='utf-8') as handle:
                set_ = (json.load(handle) or {}).get('status') == 'applied'
        except (OSError, ValueError, AttributeError):
            set_ = False
        if set_:
            checked = check_switch()
    print(json.dumps(status(pf_text=pf_show('rules'), states=pf_show('states'), model=model, check=checked)))


if __name__ == '__main__':
    main(sys.argv[1:])
