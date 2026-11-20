#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""
The pf tables of the other plugins a class names (svc-2-12, top-08), read from config.xml as the rules
hook reads them (OPNsense\\TrafficPriority\\Sources, the same rules, the same words): the groups and users
of os-useridentity - their tables hold the addresses it maps to them, where connections come from - and
the applications and categories of os-appcontrol - theirs hold the servers nDPI named as them, where
connections go. Read only: each plugin makes and fills its own tables, as aliases of type External.
status.py shows each one's state and what its table holds, and whether the next filter reload, as
config.xml is now, leaves a class with no table on one side (idle()). The switch's places are not taken
from here: the reload that left a class idle records it in its rules file (hardware.py's idle_in()).

    a group or a user   User Identity's row by its uuid; its table, the alias the row names, User
                        Identity's own (named uid_, described "User Identity: "), External, switched on,
                        the row switched on and User Identity on
    an application      by nDPI's name; its table, Application Control's alias described "Application
                        Control: " and that name, External, switched on, while it classifies
    a category          likewise, described "Application Control: category " and the name, appcontrol_cat_

Why one has no table, as the page words it: no-identity, identity-off, row-gone, row-off, no-appcontrol,
appcontrol-off, no-table, not-its, table-off (Sources.php says what each is). tools/test-sources.py and
tools/test-rules.php hold the two to one set of cases.
"""

import re

UID_PREFIX = 'uid_'
UID_DESCRIPTION = 'User Identity: '
APP_PREFIX = 'appcontrol_'
CATEGORY_PREFIX = 'appcontrol_cat_'
APP_DESCRIPTION = 'Application Control: '
CATEGORY_DESCRIPTION = 'Application Control: category '
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
TABLE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,30}')     # Sources::TABLE: an alias's name, 31 at most
CONTROL = re.compile(r'[\x00-\x1f\x7f]')
TRIM = ' \t\n\r\x00\x0b'                               # what PHP's trim() takes off
# where each plugin's model is, installed: the page says when one is not
IDENTITY_MODEL = '/usr/local/opnsense/mvc/app/models/OPNsense/UserIdentity/UserIdentity.xml'
APPCONTROL_MODEL = '/usr/local/opnsense/mvc/app/models/OPNsense/AppControl/AppControl.xml'


def items(value):
    """The items of a list field, comma-separated, each trimmed, empty ones left out (Sources::items())."""
    return [item.strip(TRIM) for item in (value or '').split(',') if item.strip(TRIM)]


def _unique(values):
    out = []
    for value in values:
        if value not in out:
            out.append(value)
    return out


def users(value):
    """The groups and users a class names, as row uuids in lower case; None when one is not a uuid."""
    out = []
    for item in items(value):
        item = item.lower()
        if not UUID.fullmatch(item):
            return None
        out.append(item)
    return _unique(out)


def names(value):
    """The applications or categories a class names; None when one holds a control character, or is longer
    than 128 bytes (Sources::names())."""
    out = []
    for item in items(value):
        if CONTROL.search(item) or len(item.encode('utf-8')) > 128:
            return None
        out.append(item)
    return _unique(out)


def _text(node, tag, default=''):
    if node is None:
        return default
    found = node.findtext(tag)
    return default if found is None else found


def aliases(root):
    """Firewall: Aliases from config.xml's root, in their order: [{'name', 'type', 'enabled', 'description'}]."""
    out = []
    for alias in (root.findall('OPNsense/Firewall/Alias/aliases/alias') if root is not None else []):
        out.append({'name': _text(alias, 'name').strip(TRIM), 'type': _text(alias, 'type').strip(TRIM),
                    'enabled': _text(alias, 'enabled', '1').strip(TRIM) == '1',
                    'description': _text(alias, 'description')})
    return out


def rows(root):
    """User Identity's rows: {uuid (lower case): {'kind' (group or user), 'name', 'alias', 'enabled'}}."""
    out = {}
    own = root.find('OPNsense/UserIdentity') if root is not None else None
    if own is None:
        return out
    for path, kind in (('groups/group', 'group'), ('users/user', 'user')):
        for row in own.findall(path):
            uuid = (row.get('uuid') or '').lower()
            if not UUID.fullmatch(uuid) or uuid in out:
                continue
            out[uuid] = {'kind': kind, 'name': _text(row, 'name').strip(TRIM), 'alias': _text(row, 'alias').strip(TRIM),
                         'enabled': _text(row, 'enabled', '1').strip(TRIM) == '1'}
    return out


def plugins(root):
    """{'identity': None | True | False, 'appcontrol': None | True | False}: None where the plugin has no
    settings in config.xml; User Identity off unless its Enabled is 1, Application Control classifying
    unless its classify is 0 (Sources::plugins())."""
    out = {'identity': None, 'appcontrol': None}
    identity = root.find('OPNsense/UserIdentity') if root is not None else None
    appcontrol = root.find('OPNsense/AppControl') if root is not None else None
    if identity is not None:
        out['identity'] = _text(identity.find('general'), 'enabled', '0').strip(TRIM) == '1'
    if appcontrol is not None:
        general = appcontrol.find('general')
        out['appcontrol'] = general is None or _text(general, 'classify', '1').strip(TRIM) == '1'
    return out


def app_tables(found, kind):
    """{nDPI's name: {'table', 'enabled'}} of Application Control's aliases of kind application or category
    (Sources::appTables()): named appcontrol_ (a category's appcontrol_cat_), described as it describes
    them, External; of two for one name, the first switched on."""
    out = {}
    for alias in found:
        name, text = alias['name'], alias['description']
        if alias['type'] != 'external' or not name.startswith(APP_PREFIX) or not text.startswith(APP_DESCRIPTION):
            continue
        category = name.startswith(CATEGORY_PREFIX) and text.startswith(CATEGORY_DESCRIPTION)
        if category != (kind == 'category'):
            continue
        key = text[len(CATEGORY_DESCRIPTION if category else APP_DESCRIPTION):]
        if key == '' or (key in out and (out[key]['enabled'] or not alias['enabled'])):
            continue
        out[key] = {'table': name, 'enabled': alias['enabled']}
    return out


def resolve(cls, found_aliases, found_rows, found_plugins):
    """What a class's groups, users, applications and categories are now (Sources::resolve()): {'from': the
    tables of its groups and users, or None when it names none; 'to': those of its applications and
    categories, or None; 'items': [{'kind', 'key', 'name', 'table' ('' when none is taken), 'why'}]}."""
    out = {'from': None, 'to': None, 'items': []}
    named = users(cls.get('users')) or []
    if named:
        out['from'] = []
        by_name = {}
        for alias in found_aliases:
            by_name.setdefault(alias['name'], alias)
        for uuid in named:
            row = found_rows.get(uuid)
            item = {'kind': (row or {}).get('kind', 'user'), 'key': uuid, 'name': (row or {}).get('name', uuid),
                    'table': '', 'why': ''}
            alias = by_name.get(row['alias']) if row is not None else None
            if found_plugins['identity'] is None:
                item['why'] = 'no-identity'
            elif not found_plugins['identity']:
                item['why'] = 'identity-off'
            elif row is None:
                item['why'] = 'row-gone'
            elif not row['enabled']:
                item['why'] = 'row-off'
            elif alias is None:
                item['why'] = 'no-table'
            elif (not alias['name'].startswith(UID_PREFIX) or not alias['description'].startswith(UID_DESCRIPTION)
                  or alias['type'] != 'external' or not TABLE.fullmatch(alias['name'])):
                item['why'] = 'not-its'
            elif not alias['enabled']:
                item['why'] = 'table-off'
            else:
                item['table'] = alias['name']
                if alias['name'] not in out['from']:
                    out['from'].append(alias['name'])
            out['items'].append(item)
    for field, kind in (('application', 'application'), ('categories', 'category')):
        wanted = names(cls.get(field)) or []
        if not wanted:
            continue
        if out['to'] is None:
            out['to'] = []
        tables = app_tables(found_aliases, kind)
        for name in wanted:
            found = tables.get(name)
            item = {'kind': kind, 'key': name, 'name': name, 'table': '', 'why': ''}
            if found_plugins['appcontrol'] is None:
                item['why'] = 'no-appcontrol'
            elif not found_plugins['appcontrol']:
                item['why'] = 'appcontrol-off'
            elif found is None or not TABLE.fullmatch(found['table']):
                item['why'] = 'no-table'
            elif not found['enabled']:
                item['why'] = 'table-off'
            else:
                item['table'] = found['table']
                if found['table'] not in out['to']:
                    out['to'].append(found['table'])
            out['items'].append(item)
    return out


def resolve_all(classes, root):
    """{uuid: resolve()} for each class, config.xml read once."""
    found_aliases, found_rows, found_plugins = aliases(root), rows(root), plugins(root)
    return {c['uuid']: resolve(c, found_aliases, found_rows, found_plugins) for c in classes}


def idle(resolved):
    """Whether a class that names tables has none on one side now: the next filter reload then writes no
    rule of its, as config.xml is now (Sources::idle())."""
    return (resolved['from'] is not None and not resolved['from']) or (resolved['to'] is not None and not resolved['to'])


def idle_side(resolved):
    """'users' or 'apps': the side with no table now; '' when neither."""
    if resolved['from'] is not None and not resolved['from']:
        return 'users'
    if resolved['to'] is not None and not resolved['to']:
        return 'apps'
    return ''
