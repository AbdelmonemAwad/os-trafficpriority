<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The model's two fields of other plugins' lists (2026-11-20): UserIdentityField offers the groups and users
 * of os-useridentity read from the configuration - by their uuid, labelled with their name, kind and alias,
 * one switched off there marked, nothing where os-useridentity is not configured, a uuid saved that no row
 * holds now kept and marked; AppControlField the applications - or, with <Kind>category</Kind>, the
 * categories - os-appcontrol keeps a table for, by the name nDPI gives, from its own aliases in Firewall:
 * Aliases as OPNsense\TrafficPriority\Sources reads them - one switched off marked, nothing where
 * os-appcontrol has none, a name saved that no table holds now kept and marked, a name a list field could
 * not hold not offered. And with either plugin removed - its model's file gone, its settings left in
 * config.xml - nothing offered, and what was saved before kept, marked as not installed (Sources::$installed
 * stands in for the files). OPNsense's classes are stood in for - the configuration by a tree of the test's
 * own, as the runner's PHP need not have its XML extension - and gettext by a catalogue of the test's own:
 *
 *   php tools/test-fields.php
 */

namespace OPNsense\Base\FieldTypes {
    /* OPNsense's BaseListField, as far as the fields use it: the options they set after loading */
    abstract class BaseListField
    {
        protected $internalOptionList = [];
        protected $internalValue = '';

        public function loaded($value = '')
        {
            $this->internalValue = $value;
            $this->actionPostLoadingEvent();
            return $this->internalOptionList;
        }

        protected function actionPostLoadingEvent()
        {
        }
    }
}

namespace OPNsense\Core {
    /* the configuration as the fields read it: Config::getInstance()->object() */
    class Config
    {
        public static $root = null;
        private static $me;

        public static function getInstance()
        {
            return self::$me ??= new Config();
        }

        public function object()
        {
            return self::$root;
        }
    }
}

namespace OPNsense\TrafficPriority\FieldTypes {
    function gettext($text)
    {
        return $GLOBALS['translations'][$text] ?? $text;
    }
}

namespace {
    const G_STAFF = '7a1c2e30-5b6d-4e8f-9a0b-1c2d3e4f5a01';
    const U_ALICE = '7a1c2e30-5b6d-4e8f-9a0b-1c2d3e4f5a02';
    const U_CAROL = '7a1c2e30-5b6d-4e8f-9a0b-1c2d3e4f5a04';
    const U_GONE = '7a1c2e30-5b6d-4e8f-9a0b-1c2d3e4f5a07';

    /*
     * A configuration tree as SimpleXML gives it, as far as the fields read one: $node->child (the first of
     * that name, and all of them when iterated), isset() of a child, $node['attribute'], (string).
     */
    class XSet implements \IteratorAggregate, \ArrayAccess
    {
        public $items;

        public function __construct($items)
        {
            $this->items = $items;
        }

        public function getIterator(): \Iterator
        {
            return new \ArrayIterator($this->items);
        }

        public function __get($name)
        {
            return $this->items ? $this->items[0]->__get($name) : new XSet([]);
        }

        public function __isset($name)
        {
            return $this->items && $this->items[0]->__isset($name);
        }

        public function __toString()
        {
            return $this->items ? (string)$this->items[0] : '';
        }

        public function offsetExists($key): bool
        {
            return $this->items && isset($this->items[0]->attrs[$key]);
        }

        public function offsetGet($key): mixed
        {
            return $this->items ? ($this->items[0]->attrs[$key] ?? null) : null;
        }

        public function offsetSet($key, $value): void
        {
        }

        public function offsetUnset($key): void
        {
        }
    }

    class XNode implements \ArrayAccess
    {
        public $tag;
        public $attrs;
        public $text;
        public $children;

        public function __construct($tag, $attrs = [], $children = [], $text = '')
        {
            $this->tag = $tag;
            $this->attrs = $attrs;
            $this->children = $children;
            $this->text = $text;
        }

        public function __get($name)
        {
            return new XSet(array_values(array_filter($this->children, function ($c) use ($name) {
                return $c->tag === $name;
            })));
        }

        public function __isset($name)
        {
            foreach ($this->children as $child) {
                if ($child->tag === $name) {
                    return true;
                }
            }
            return false;
        }

        public function __toString()
        {
            return $this->text;
        }

        public function offsetExists($key): bool
        {
            return isset($this->attrs[$key]);
        }

        public function offsetGet($key): mixed
        {
            return $this->attrs[$key] ?? null;
        }

        public function offsetSet($key, $value): void
        {
        }

        public function offsetUnset($key): void
        {
        }
    }

    function el($tag, $children = [], $attrs = [])
    {
        return new XNode($tag, $attrs, $children);
    }

    function leaf($tag, $text)
    {
        return new XNode($tag, [], [], $text);
    }

    function row($tag, $uuid, $name, $alias, $enabled = '1')
    {
        return el($tag, [leaf('enabled', $enabled), leaf('name', $name), leaf('alias', $alias)], ['uuid' => $uuid]);
    }

    function alias($name, $description, $enabled = '1', $type = 'external')
    {
        $children = [leaf('name', $name), leaf('type', $type), leaf('description', $description)];
        if ($enabled !== null) {
            $children[] = leaf('enabled', $enabled);
        }
        return el('alias', $children);
    }

    /* the configuration's root: User Identity's settings (null: none) and Firewall: Aliases */
    function config($identity, $aliases = [])
    {
        $own = $identity === null ? [] : [el('UserIdentity', $identity)];
        $own[] = el('Firewall', [el('Alias', [el('aliases', $aliases)])]);
        return el('opnsense', [el('OPNsense', $own)]);
    }

    $root = dirname(__DIR__);
    $GLOBALS['translations'] = [];
    $failed = 0;
    $checks = 0;

    function check($ok, $what)
    {
        global $failed, $checks;
        $checks++;
        if (!$ok) {
            $failed++;
            echo "FAIL $what\n";
        }
    }

    require $root . '/src/opnsense/mvc/app/library/OPNsense/TrafficPriority/Sources.php';
    require $root . '/src/opnsense/mvc/app/models/OPNsense/TrafficPriority/FieldTypes/UserIdentityField.php';
    require $root . '/src/opnsense/mvc/app/models/OPNsense/TrafficPriority/FieldTypes/AppControlField.php';

    use OPNsense\Core\Config;
    use OPNsense\TrafficPriority\FieldTypes\AppControlField;
    use OPNsense\TrafficPriority\FieldTypes\UserIdentityField;
    use OPNsense\TrafficPriority\Sources;

    /* both plugins installed - their model files there - unless a case says otherwise */
    Sources::$installed = ['identity' => true, 'appcontrol' => true];

    /* the field's static cache emptied, so each case reads its own configuration */
    function fresh($class)
    {
        $cache = new ReflectionProperty($class, 'cache');
        if (PHP_VERSION_ID < 80100) {
            $cache->setAccessible(true);
        }
        $cache->setValue(null, $class === UserIdentityField::class ? null : []);
    }

    /* ---- User Identity's groups and users ---- */
    $identity = [
        el('groups', [row('group', G_STAFF, 'Staff', 'uid_staff')]),
        el('users', [row('user', U_ALICE, 'alice', 'uid_alice'), row('user', U_CAROL, 'carol', 'uid_carol', '0'),
            row('user', 'not-a-uuid', 'mallory', 'uid_mallory'), row('user', U_GONE . 'x', 'trent', 'uid_trent'),
            row('user', '7a1c2e30-5b6d-4e8f-9a0b-1c2d3e4f5a08', "eve<b>\n", 'uid_eve')]),
    ];
    $options = UserIdentityField::rowOptions(config($identity));
    check($options === [U_ALICE => 'alice (a user, uid_alice)', U_CAROL => 'carol (a user, uid_carol) - switched off in User Identity',
        '7a1c2e30-5b6d-4e8f-9a0b-1c2d3e4f5a08' => 'eve b (a user, uid_eve)', G_STAFF => 'Staff (a group, uid_staff)'],
        'groups and users by uuid, labelled with name, kind and alias, sorted; one switched off marked; a row without a uuid ' .
        'left out; a name with < > and a line break shown plain: ' . json_encode($options));
    check(UserIdentityField::rowOptions(config(null)) === [], 'User Identity not configured: nothing offered');
    $odd = UserIdentityField::rowOptions(config([el('users', [row('user', U_ALICE, 'alice', 'uid_alice', ''),
        el('user', [leaf('name', 'carol'), leaf('alias', 'uid_carol')], ['uuid' => U_CAROL])])]));
    check($odd === [U_ALICE => 'alice (a user, uid_alice) - switched off in User Identity', U_CAROL => 'carol (a user, uid_carol)'],
        'an empty enabled element: off, as the rules hook reads it; none at all: on, the model\'s default: ' . json_encode($odd));
    Config::$root = config($identity);
    fresh(UserIdentityField::class);
    $loaded = (new UserIdentityField())->loaded(U_ALICE . ',' . U_GONE);
    check(($loaded[U_GONE] ?? null) === U_GONE . ' (not in User Identity now)' && isset($loaded[U_ALICE]),
        'a uuid saved that no row holds now: kept, marked');
    check(!isset((new UserIdentityField())->loaded('nonsense')['nonsense']), 'a saved value that is no uuid: not made an option');
    $GLOBALS['translations'] = ['%s (a group, %s)' => '%s [group %s]', '%s (a user, %s)' => '%s %s %s'];
    $translated = UserIdentityField::rowOptions(config($identity));
    check(($translated[G_STAFF] ?? '') === 'Staff [group uid_staff]' && ($translated[U_ALICE] ?? '') === 'alice (a user, uid_alice)',
        'a translation filled; one whose %s do not fit falls back to the English');
    $GLOBALS['translations'] = [];
    /* os-useridentity removed: its rows stay in config.xml, as its uninstall.sh leaves its settings (P6) */
    check(UserIdentityField::rowOptions(config($identity), false) === [],
        'User Identity not installed, its rows left in config.xml: nothing offered');
    Sources::$installed = ['identity' => false, 'appcontrol' => true];
    fresh(UserIdentityField::class);
    $loaded = (new UserIdentityField())->loaded(U_ALICE . ',' . U_GONE);
    check($loaded === [U_ALICE => 'alice (a user, uid_alice) - User Identity is not installed',
        U_GONE => U_GONE . ' (not in User Identity now)'],
        'User Identity not installed: no row offered; a row saved before its removal kept, named and marked as not installed; ' .
        'one no row holds marked as before: ' . json_encode($loaded));
    Sources::$installed = ['identity' => true, 'appcontrol' => true];
    fresh(UserIdentityField::class);

    /* ---- Application Control's applications and categories ---- */
    $aliases = [
        alias('appcontrol_Zoom', 'Application Control: Zoom'),
        alias('appcontrol_Teams', 'Application Control: Teams', '0'),
        alias('appcontrol_cat_VoIP', 'Application Control: category VoIP'),
        alias('appcontrol_cat_Video', 'Application Control: category Video', null),
        /* the owner's own, of a name like the plugin's: not Application Control's */
        alias('appcontrol_mine', 'my own list'),
        alias('appcontrol_Host', 'Application Control: Host', '1', 'host'),
        alias('appcontrol_Odd', 'Application Control: odd,name'),
        alias('uid_alice', 'User Identity: user alice'),
    ];
    $apps = AppControlField::nameOptions('application', config(null, $aliases));
    check($apps === ['Teams' => 'Teams - switched off in Application Control', 'Zoom' => 'Zoom'],
        'the applications with a table: by name, one switched off marked; a category, the owner\'s, one not External, one ' .
        'whose name holds a comma, User Identity\'s - none offered: ' . json_encode($apps));
    $cats = AppControlField::nameOptions('category', config(null, $aliases));
    check($cats === ['Video' => 'Video', 'VoIP' => 'VoIP'],
        'the categories with a table, by name - a table with no enabled element on, as the Alias model\'s default: ' . json_encode($cats));
    check(AppControlField::nameOptions('application', config(null)) === [], 'no alias of Application Control\'s: nothing offered');
    Config::$root = config(null, $aliases);
    fresh(AppControlField::class);
    $field = new AppControlField();
    $loaded = $field->loaded('Zoom,Netflix');
    check(($loaded['Netflix'] ?? null) === 'Netflix (no table in Application Control now)' && ($loaded['Zoom'] ?? null) === 'Zoom',
        'an application saved that no table holds now: kept, marked');
    $field = new AppControlField();
    $field->setKind('category');
    $loaded = $field->loaded('VoIP');
    check(array_keys($loaded) === ['Video', 'VoIP'], 'Kind category: the categories, each kind cached apart: ' . json_encode($loaded));
    $field = new AppControlField();
    $field->setKind('nonsense');
    check(isset($field->loaded('')['Zoom']), 'an unknown Kind: applications, the default');
    /* os-appcontrol removed, an alias of its left (switched off where something still names it) */
    check(AppControlField::nameOptions('application', config(null, $aliases), false) === [],
        'Application Control not installed: nothing offered, whatever aliases of its are left');
    Sources::$installed = ['identity' => true, 'appcontrol' => false];
    fresh(AppControlField::class);
    $loaded = (new AppControlField())->loaded('Zoom');
    check($loaded === ['Zoom' => 'Zoom - Application Control is not installed'],
        'Application Control not installed: a name saved before its removal kept, marked as not installed: ' . json_encode($loaded));
    Sources::$installed = ['identity' => true, 'appcontrol' => true];

    echo ($failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n");
    exit($failed ? 1 : 0);
}
