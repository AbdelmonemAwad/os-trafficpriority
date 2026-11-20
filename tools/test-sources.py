#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""sources.py: the tables of the other plugins a class names, against config.xml files written here as
OPNsense keeps them - User Identity's group and user rows and its aliases (uid_..., "User Identity: "),
Application Control's aliases of applications and categories ("Application Control: ...") - in the same
cases tools/test-rules.php gives the rules hook's Sources.php: each table taken only as its plugin's own,
External and switched on, while that plugin is on and the row is switched on; why each other one has none;
a table named twice taken once; and a class with no table on one side idle.

    python3 tools/test-sources.py"""
import os
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'trafficpriority'))
import sources  # noqa: E402

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


G_STAFF = '7a1c2e30-5b6d-4e8f-9a0b-1c2d3e4f5a01'
U_ALICE = '7a1c2e30-5b6d-4e8f-9a0b-1c2d3e4f5a02'
U_BOB = '7a1c2e30-5b6d-4e8f-9a0b-1c2d3e4f5a03'
U_OFF = '7a1c2e30-5b6d-4e8f-9a0b-1c2d3e4f5a04'
U_UNAPPLIED = '7a1c2e30-5b6d-4e8f-9a0b-1c2d3e4f5a05'
U_STRANGER = '7a1c2e30-5b6d-4e8f-9a0b-1c2d3e4f5a06'
U_GONE = '7a1c2e30-5b6d-4e8f-9a0b-1c2d3e4f5a07'

ALIASES = [
    ('uid_staff', 'external', '1', 'User Identity: group Staff'),
    ('uid_alice', 'external', '1', 'User Identity: user alice'),
    ('uid_bob', 'external', '0', 'User Identity: user bob'),
    ('uid_stranger', 'host', '1', 'my own list'),
    ('appcontrol_Zoom', 'external', '1', 'Application Control: Zoom'),
    ('appcontrol_Teams', 'external', '1', 'Application Control: Teams'),
    ('appcontrol_YouTube', 'external', '0', 'Application Control: YouTube'),
    ('appcontrol_cat_VoIP', 'external', '1', 'Application Control: category VoIP'),
]


def config(identity='1', classify='1', aliases=None, extra=''):
    """config.xml with the other plugins' settings and aliases, as tools/test-rules.php's withTables(); ''
    leaves a plugin out, as where it is not installed."""
    body = ''.join('<alias><name>%s</name><type>%s</type><enabled>%s</enabled><description>%s</description></alias>'
                   % a for a in (ALIASES if aliases is None else aliases))
    who = ''
    if identity != '':
        rows = [(U_ALICE, '1', 'alice', 'uid_alice'), (U_BOB, '1', 'bob', 'uid_bob'), (U_OFF, '0', 'carol', 'uid_carol'),
                (U_UNAPPLIED, '1', 'dave', 'uid_dave'), (U_STRANGER, '1', 'erin', 'uid_stranger')]
        who = ('<UserIdentity><general><enabled>%s</enabled></general><groups><group uuid="%s"><enabled>1</enabled>'
               '<name>Staff</name><alias>uid_staff</alias></group></groups><users>%s</users></UserIdentity>'
               % (identity, G_STAFF, ''.join('<user uuid="%s"><enabled>%s</enabled><name>%s</name><alias>%s</alias></user>'
                                             % r for r in rows)))
    apps = '' if classify == '' else '<AppControl><general><classify>%s</classify></general></AppControl>' % classify
    return ET.fromstring('<opnsense><OPNsense>%s%s<Firewall><Alias><aliases>%s</aliases></Alias></Firewall>%s</OPNsense>'
                         '</opnsense>' % (who, apps, body, extra))


def resolve(cls, root=None):
    root = config() if root is None else root
    return sources.resolve(cls, sources.aliases(root), sources.rows(root), sources.plugins(root))


def whys(found):
    return [(i['key'], i['table'], i['why']) for i in found['items']]


# ---- the parts ----
check('items: comma-separated, trimmed as PHP trims, empty ones left out', sources.items(' a ,, b\n,'), ['a', 'b'])
check('users: lower case, each once', sources.users(U_ALICE.upper() + ',' + U_ALICE), [U_ALICE])
check('users: one that is no uuid - None', sources.users(U_ALICE + ',bob'), None)
check('users: none', sources.users(''), [])
check('names: as written, each once', sources.names('Zoom,Teams,Zoom'), ['Zoom', 'Teams'])
check('names: a line break or another control character - None',
      [sources.names('Zo\nom'), sources.names('Vo\x01IP'), sources.names('x' * 129)], [None, None, None])
check('names: 128 bytes, and a name of letters not Latin: taken', [len(sources.names('x' * 128)[0]),
                                                                  sources.names('اب')], [128, ['اب']])
check('plugins: both on', sources.plugins(config()), {'identity': True, 'appcontrol': True})
check('plugins: User Identity off, Application Control not classifying',
      sources.plugins(config('0', '0')), {'identity': False, 'appcontrol': False})
check('plugins: neither installed', sources.plugins(config('', '')), {'identity': None, 'appcontrol': None})
check('plugins: Application Control with no classify set classifies, as its hook has it',
      sources.plugins(ET.fromstring('<opnsense><OPNsense><AppControl><general/></AppControl></OPNsense></opnsense>')),
      {'identity': None, 'appcontrol': True})
check('plugins: an empty classify is off, as PHP reads it',
      sources.plugins(ET.fromstring('<opnsense><OPNsense><AppControl><general><classify/></general></AppControl>'
                                    '</OPNsense></opnsense>'))['appcontrol'], False)
check('rows: by uuid, groups and users, switched on or off',
      {u: (r['kind'], r['alias'], r['enabled']) for u, r in sources.rows(config()).items() if u in (G_STAFF, U_OFF)},
      {G_STAFF: ('group', 'uid_staff', True), U_OFF: ('user', 'uid_carol', False)})
apps = sources.app_tables(sources.aliases(config()), 'application')
check('app_tables: the applications by nDPI\'s name, a category\'s alias not among them',
      {k: (v['table'], v['enabled']) for k, v in apps.items()},
      {'Zoom': ('appcontrol_Zoom', True), 'Teams': ('appcontrol_Teams', True), 'YouTube': ('appcontrol_YouTube', False)})
check('app_tables: the categories', {k: v['table'] for k, v in sources.app_tables(sources.aliases(config()), 'category').items()},
      {'VoIP': 'appcontrol_cat_VoIP'})
twice = [('appcontrol_Zoom', 'external', '0', 'Application Control: Zoom'),
         ('appcontrol_Zoom_1a2b', 'external', '1', 'Application Control: Zoom')]
check('app_tables: of two for one name, the one switched on', sources.app_tables(
    sources.aliases(config(aliases=twice)), 'application')['Zoom']['table'], 'appcontrol_Zoom_1a2b')

# ---- a class's tables ----
found = resolve({'users': G_STAFF})
check('a group: its table, the source', (found['from'], found['to'], whys(found)), (['uid_staff'], None,
                                                                                   [(G_STAFF, 'uid_staff', '')]))
found = resolve({'application': 'Zoom'})
check('an application: its table, the destination', (found['from'], found['to']), (None, ['appcontrol_Zoom']))
found = resolve({'users': G_STAFF + ',' + U_ALICE, 'application': 'Zoom,Teams', 'categories': 'VoIP'})
check('groups, users, applications and a category: every table, each side', (found['from'], found['to']),
      (['uid_staff', 'uid_alice'], ['appcontrol_Zoom', 'appcontrol_Teams', 'appcontrol_cat_VoIP']))
check('...each item with its kind and name', [(i['kind'], i['name']) for i in found['items']],
      [('group', 'Staff'), ('user', 'alice'), ('application', 'Zoom'), ('application', 'Teams'), ('category', 'VoIP')])
found = resolve({'users': U_ALICE + ',' + U_ALICE.upper()})
check('a user named twice: taken once', found['from'], ['uid_alice'])
for what, cls, root, want in (
        ('User Identity off', {'users': U_ALICE}, config('0'), 'identity-off'),
        ('User Identity not installed', {'users': U_ALICE}, config(''), 'no-identity'),
        ('a row switched off', {'users': U_OFF}, None, 'row-off'),
        ('a row no longer there', {'users': U_GONE}, None, 'row-gone'),
        ('a row not applied in User Identity yet', {'users': U_UNAPPLIED}, None, 'no-table'),
        ('a row whose alias is the owner\'s', {'users': U_STRANGER}, None, 'not-its'),
        ('a user\'s table switched off', {'users': U_BOB}, None, 'table-off'),
        ('Application Control not installed', {'application': 'Zoom'}, config('1', ''), 'no-appcontrol'),
        ('Application Control not classifying', {'application': 'Zoom'}, config('1', '0'), 'appcontrol-off'),
        ('an application without a table', {'application': 'Netflix'}, None, 'no-table'),
        ('an application\'s table switched off', {'application': 'YouTube'}, None, 'table-off'),
        ('a category named as an application', {'application': 'VoIP'}, None, 'no-table'),
        ('an application named as a category', {'categories': 'Zoom'}, None, 'no-table')):
    found = resolve(cls, root)
    side = found['from'] if 'users' in cls else found['to']
    check(what + ': no table, why said, the class idle',
          (side, [i['why'] for i in found['items']], sources.idle(found)), ([], [want], True))
found = resolve({'users': U_ALICE, 'application': 'Netflix'})
check('a user with a table, no application with one: idle, the applications\' side', (sources.idle(found),
                                                                                      sources.idle_side(found)), (True, 'apps'))
found = resolve({'users': U_GONE, 'application': 'Zoom'})
check('no user with a table: the users\' side', sources.idle_side(found), 'users')
found = resolve({'users': U_ALICE + ',' + U_OFF + ',' + U_GONE, 'application': 'Zoom,Netflix'})
check('of several, the ones with a table; not idle', (found['from'], found['to'], sources.idle(found)),
      (['uid_alice'], ['appcontrol_Zoom'], False))
found = resolve({'users': 'not-a-uuid', 'application': 'Zo\nom'})
check('values no table could be found by: the class names none (its rule is the model\'s and the hook\'s problem)',
      (found['from'], found['to'], sources.idle(found)), (None, None, False))
check('a class that names nothing of them: none, not idle', sources.idle(resolve({'destination_port': '5060'})), False)
odd = ALIASES + [('appcontrol_Bad\nname', 'external', '1', 'Application Control: Bad')]
check('an alias named with a line break: no table', whys(resolve({'application': 'Bad'}, config(aliases=odd))),
      [('Bad', '', 'no-table')])
long_name = 'uid_' + 'x' * 28
root = ET.fromstring('<opnsense><OPNsense><UserIdentity><general><enabled>1</enabled></general><users><user uuid="%s">'
                     '<enabled>1</enabled><name>alice</name><alias>%s</alias></user></users></UserIdentity><Firewall><Alias>'
                     '<aliases><alias><name>%s</name><type>external</type><enabled>1</enabled><description>User Identity: '
                     'user alice</description></alias></aliases></Alias></Firewall></OPNsense></opnsense>'
                     % (U_ALICE, long_name, long_name))
check('an alias name of 32 characters: not taken, as pf could not hold it', whys(resolve({'users': U_ALICE}, root)),
      [(U_ALICE, '', 'not-its')])
all_ = sources.resolve_all([{'uuid': 'a', 'users': U_GONE}, {'uuid': 'b', 'application': 'Zoom'}], config())
check('resolve_all: each class by its uuid, config.xml read once', {u: sources.idle(r) for u, r in all_.items()},
      {'a': True, 'b': False})

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
