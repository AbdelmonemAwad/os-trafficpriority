<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\TrafficPriority;

/**
 * The pf tables of the other plugins a class names (svc-2-12, top-08), found in the configuration at
 * every filter reload: the groups and users of os-useridentity, whose tables hold the addresses it maps
 * to them - the devices the connections come from - and the applications and categories of
 * os-appcontrol, whose tables hold the servers nDPI named as them - where the connections go. Neither is
 * written here: each plugin makes and fills its own tables, as aliases of type External in Firewall:
 * Aliases, and this reads which are there. scripts/trafficpriority/sources.py reads them the same way
 * for the page and the switch; tools/test-sources.py and tools/test-rules.php hold the two to one set of
 * cases.
 *
 *   a group or a user   a row of User Identity's (OPNsense/UserIdentity/groups/group, users/user), by
 *                       its uuid - the key it keeps whatever the row's name becomes - whose table is the
 *                       alias the row names (uid_...), User Identity's own: named uid_, described
 *                       "User Identity: " (its Aliases.php)
 *   an application      the name nDPI gives it, the key os-appcontrol's own settings keep; its table is
 *                       the alias of Application Control's described "Application Control: " and that
 *                       name (its tables.py, appcontrol.inc)
 *   a category          likewise, the alias described "Application Control: category " and the name,
 *                       named appcontrol_cat_
 *
 * A table is taken only as the alias of the plugin it belongs to, External and switched on - one of
 * another name or another owner is no table, nor is one switched off, which its plugin switches off
 * rather than removes while something else names it, and no longer keeps - and only while that plugin
 * is on: User Identity's Enabled, Application Control's classifying (on unless set to 0). A group or a
 * user also needs its row there and switched on. Whatever is not, says why, in one word the page turns
 * into a sentence:
 *
 *   no-identity       User Identity has no settings here: not installed, or never set
 *   identity-off      User Identity is off: it keeps no table
 *   row-gone          no row of User Identity's holds that uuid now
 *   row-off           the row is switched off in User Identity
 *   no-appcontrol     Application Control has no settings here: not installed, or never set
 *   appcontrol-off    Application Control is not classifying: it keeps no table
 *   no-table          the alias is not in Firewall: Aliases - not applied in that plugin yet, or for an
 *                     application, not chosen there for a table
 *   not-its           an alias of the row's name that is not User Identity's own, or not External
 *   table-off         the alias is switched off
 *
 * Nothing here throws: the rules hook calls it during a filter reload, which an exception would stop.
 */
class Sources
{
    const UID_PREFIX = 'uid_';
    const UID_DESCRIPTION = 'User Identity: ';
    const APP_PREFIX = 'appcontrol_';
    const CATEGORY_PREFIX = 'appcontrol_cat_';
    const APP_DESCRIPTION = 'Application Control: ';
    const CATEGORY_DESCRIPTION = 'Application Control: category ';
    const UUID = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/D';
    /* an alias's name as OPNsense takes it - 31 characters at most, pf's table names (PF_TABLE_NAME_SIZE
       less the end) - and as the rule is given it: never anything that could break a line of the rules file */
    const TABLE = '/^[A-Za-z_][A-Za-z0-9_]{0,30}$/D';

    /**
     * The items of a list field, comma-separated as OPNsense keeps them, each trimmed, empty ones left out.
     */
    public static function items($value)
    {
        $out = [];
        foreach (explode(',', (string)$value) as $item) {
            $item = trim($item);
            if ($item !== '') {
                $out[] = $item;
            }
        }
        return $out;
    }

    /**
     * The groups and users a class names, as row uuids in lower case; null when one is not a uuid
     * (config.xml written by other means: Marking::problem() 'users').
     */
    public static function users($value)
    {
        $out = [];
        foreach (self::items($value) as $item) {
            $item = strtolower($item);
            if (!preg_match(self::UUID, $item)) {
                return null;
            }
            $out[] = $item;
        }
        return array_values(array_unique($out));
    }

    /**
     * The applications or categories a class names, as nDPI names them; null when one holds a control
     * character - a line break among them - which no name nDPI gives does (Marking::problem() 'application').
     */
    public static function names($value)
    {
        $out = [];
        foreach (self::items($value) as $item) {
            if (preg_match('/[\x00-\x1f\x7f]/', $item) || strlen($item) > 128) {
                return null;
            }
            $out[] = $item;
        }
        return array_values(array_unique($out));
    }

    /**
     * A list of config.xml's legacy array (Config.php's toArray()) as a list: one item is an array of its
     * fields, several a list of them.
     */
    private static function listOf($node)
    {
        if (!is_array($node)) {
            return [];
        }
        return array_is_list($node) ? $node : [$node];
    }

    private static function text($node, $key, $default = '')
    {
        $value = is_array($node) ? ($node[$key] ?? null) : null;
        return is_string($value) ? $value : $default;
    }

    /**
     * Firewall: Aliases from config.xml's legacy array, in their order there: [['name', 'type', 'enabled'
     * (bool), 'description'], ...].
     */
    public static function aliases($config)
    {
        $out = [];
        foreach (self::listOf($config['OPNsense']['Firewall']['Alias']['aliases']['alias'] ?? null) as $alias) {
            if (!is_array($alias)) {
                continue;
            }
            $out[] = [
                'name' => trim(self::text($alias, 'name')),
                'type' => trim(self::text($alias, 'type')),
                'enabled' => trim(self::text($alias, 'enabled', '1')) === '1',
                'description' => self::text($alias, 'description'),
            ];
        }
        return $out;
    }

    /**
     * User Identity's rows from config.xml's legacy array: uuid (lower case) => ['kind' (group or user),
     * 'name', 'alias', 'enabled' (bool)].
     */
    public static function rows($config)
    {
        $out = [];
        $own = $config['OPNsense']['UserIdentity'] ?? null;
        foreach ([['groups', 'group'], ['users', 'user']] as $where) {
            foreach (self::listOf($own[$where[0]][$where[1]] ?? null) as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $uuid = strtolower((string)($row['@attributes']['uuid'] ?? ''));
                if (!preg_match(self::UUID, $uuid) || isset($out[$uuid])) {
                    continue;
                }
                $out[$uuid] = [
                    'kind' => $where[1],
                    'name' => trim(self::text($row, 'name')),
                    'alias' => trim(self::text($row, 'alias')),
                    'enabled' => trim(self::text($row, 'enabled', '1')) === '1',
                ];
            }
        }
        return $out;
    }

    /**
     * Whether each plugin has settings here, and is on: ['identity' => null | true | false, 'appcontrol'
     * => null | true | false], null where it has none. User Identity is off unless its Enabled is 1;
     * Application Control classifies unless its classify is 0 - an element there and empty is off, as its
     * own hook reads it (appcontrol_enabled()).
     */
    public static function plugins($config)
    {
        $identity = $config['OPNsense']['UserIdentity'] ?? null;
        $appcontrol = $config['OPNsense']['AppControl'] ?? null;
        $out = ['identity' => null, 'appcontrol' => null];
        if (is_array($identity) || is_string($identity)) {
            $out['identity'] = trim(self::text($identity['general'] ?? null, 'enabled', '0')) === '1';
        }
        if (is_array($appcontrol) || is_string($appcontrol)) {
            $general = is_array($appcontrol) ? ($appcontrol['general'] ?? null) : null;
            $out['appcontrol'] = !is_array($general) || trim(self::text($general, 'classify', '1')) === '1';
        }
        return $out;
    }

    /**
     * Application Control's tables by the name nDPI gives: [name => ['table', 'enabled']] of its aliases of
     * $kind, application or category - each named appcontrol_ (a category's appcontrol_cat_) and described
     * as its plugin describes it, External. Of two for one name, the first switched on.
     */
    public static function appTables(array $aliases, $kind)
    {
        $out = [];
        foreach ($aliases as $alias) {
            $name = $alias['name'];
            $text = $alias['description'];
            if ($alias['type'] !== 'external' || strpos($name, self::APP_PREFIX) !== 0 ||
                strpos($text, self::APP_DESCRIPTION) !== 0) {
                continue;
            }
            $category = strpos($name, self::CATEGORY_PREFIX) === 0 && strpos($text, self::CATEGORY_DESCRIPTION) === 0;
            if ($category !== ($kind === 'category')) {
                continue;
            }
            $key = substr($text, strlen($category ? self::CATEGORY_DESCRIPTION : self::APP_DESCRIPTION));
            if ($key === '' || (isset($out[$key]) && ($out[$key]['enabled'] || !$alias['enabled']))) {
                continue;
            }
            $out[$key] = ['table' => $name, 'enabled' => $alias['enabled']];
        }
        return $out;
    }

    /**
     * What a class's groups, users, applications and categories are now: ['from' => the tables of its
     * groups and users, or null when it names none; 'to' => those of its applications and categories, or
     * null; 'items' => [['kind' (group, user, application, category), 'key' (a row's uuid or nDPI's name),
     * 'name' (what the page shows), 'table' (the alias, '' when none is taken), 'why' ('' or a word
     * above)], ...]]. A table named twice is taken once. $class's fields as config.xml holds them;
     * $aliases from aliases(), $rows from rows(), $plugins from plugins().
     */
    public static function resolve(array $class, array $aliases, array $rows, array $plugins)
    {
        $out = ['from' => null, 'to' => null, 'items' => []];
        $users = self::users($class['users'] ?? '') ?? [];
        if (!empty($users)) {
            $out['from'] = [];
            $byName = [];
            foreach ($aliases as $alias) {
                $byName[$alias['name']] = $byName[$alias['name']] ?? $alias;
            }
            foreach ($users as $uuid) {
                $row = $rows[$uuid] ?? null;
                $item = ['kind' => $row['kind'] ?? 'user', 'key' => $uuid, 'name' => $row['name'] ?? $uuid,
                    'table' => '', 'why' => ''];
                $alias = $row !== null ? ($byName[$row['alias']] ?? null) : null;
                if ($plugins['identity'] === null) {
                    $item['why'] = 'no-identity';
                } elseif (!$plugins['identity']) {
                    $item['why'] = 'identity-off';
                } elseif ($row === null) {
                    $item['why'] = 'row-gone';
                } elseif (!$row['enabled']) {
                    $item['why'] = 'row-off';
                } elseif ($alias === null) {
                    $item['why'] = 'no-table';
                } elseif (strpos($alias['name'], self::UID_PREFIX) !== 0 ||
                    strpos($alias['description'], self::UID_DESCRIPTION) !== 0 || $alias['type'] !== 'external' ||
                    !preg_match(self::TABLE, $alias['name'])) {
                    $item['why'] = 'not-its';
                } elseif (!$alias['enabled']) {
                    $item['why'] = 'table-off';
                } else {
                    $item['table'] = $alias['name'];
                    if (!in_array($alias['name'], $out['from'], true)) {
                        $out['from'][] = $alias['name'];
                    }
                }
                $out['items'][] = $item;
            }
        }
        foreach (['application' => 'application', 'categories' => 'category'] as $field => $kind) {
            $names = self::names($class[$field] ?? '') ?? [];
            if (empty($names)) {
                continue;
            }
            $out['to'] = $out['to'] ?? [];
            $tables = self::appTables($aliases, $kind);
            foreach ($names as $name) {
                $found = $tables[$name] ?? null;
                $item = ['kind' => $kind, 'key' => $name, 'name' => $name, 'table' => '', 'why' => ''];
                if ($plugins['appcontrol'] === null) {
                    $item['why'] = 'no-appcontrol';
                } elseif (!$plugins['appcontrol']) {
                    $item['why'] = 'appcontrol-off';
                } elseif ($found === null || !preg_match(self::TABLE, $found['table'])) {
                    $item['why'] = 'no-table';
                } elseif (!$found['enabled']) {
                    $item['why'] = 'table-off';
                } else {
                    $item['table'] = $found['table'];
                    if (!in_array($found['table'], $out['to'], true)) {
                        $out['to'][] = $found['table'];
                    }
                }
                $out['items'][] = $item;
            }
        }
        return $out;
    }

    /**
     * resolve() for a class, from config.xml's legacy array.
     */
    public static function resolveIn(array $class, $config)
    {
        return self::resolve($class, self::aliases($config), self::rows($config), self::plugins($config));
    }

    /**
     * Whether a class whose rules need a table has none on one side now: it names groups or users and none
     * of them has one, or applications or categories and none of them has one. It then makes no rule -
     * never one widened to every source or destination - while it keeps its place in the switch, which
     * its settings, not the other plugins', decide.
     */
    public static function idle(array $resolved)
    {
        return ($resolved['from'] !== null && empty($resolved['from'])) ||
            ($resolved['to'] !== null && empty($resolved['to']));
    }
}
