<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\TrafficPriority\FieldTypes;

use OPNsense\Base\FieldTypes\BaseListField;
use OPNsense\Core\Config;
use OPNsense\TrafficPriority\Sources;

/**
 * The groups and users of os-useridentity a class takes (top-08): its group rows and its user rows, read
 * from config.xml (OPNsense/UserIdentity), each by its uuid - the key os-useridentity keeps for a row
 * whatever its name becomes - and labelled with its name, its kind and the alias of its table, as
 * os-blocklists' web policies by user offer them. Read from the configuration, not through
 * os-useridentity's model, so the field loads where os-useridentity is not installed: it then offers
 * nothing, and the page says why - installed by its model's file, as the rules hook reads it
 * (Sources::installed()), since its removal leaves its rows in config.xml. A row saved before the removal
 * stays an option, marked as not installed. A row switched off in User Identity is offered, marked so - a
 * class takes no table through it while it is off. A uuid saved that no row holds now (the row deleted in
 * User Identity) stays an option, marked so, rather than vanish from the field and from the next save;
 * the rules hook takes no table by it (OPNsense\TrafficPriority\Sources). A value that is not an option
 * fails the model's validation, as an OptionField's does.
 */
class UserIdentityField extends BaseListField
{
    const UUID = '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/D';

    private static $cache = null;

    /**
     * a translated format filled, or the English one where the translation's %s do not fit
     */
    private static function fill($format, $english, ...$args)
    {
        foreach ([$format, $english] as $candidate) {
            try {
                $result = @vsprintf($candidate, $args);
            } catch (\Throwable $e) {
                $result = false;
            }
            if (is_string($result)) {
                return $result;
            }
        }
        return $english;
    }

    /**
     * one line of text from the configuration as an option may show it: no control characters, no < or >
     */
    private static function plain($text, $length)
    {
        $text = preg_replace('/[^\x20-\x7e\x{a0}-\x{ffff}]/u', '', str_replace(['<', '>'], ' ', (string)$text));
        $text = trim(preg_replace('/\s+/u', ' ', $text ?? '') ?? '');
        return function_exists('mb_substr') ? mb_substr($text, 0, $length) : substr($text, 0, $length);
    }

    /**
     * The rows offered: none where os-useridentity is not installed.
     * @param \SimpleXMLElement|null $root the configuration's root, config.xml's by default
     * @param bool|null $installed whether os-useridentity is; by its model's file when not given
     * @return array uuid => label, sorted by label
     */
    public static function rowOptions($root = null, $installed = null)
    {
        return ($installed ?? Sources::installed()['identity']) ? self::rowLabels($root) : [];
    }

    /**
     * Every row's label, as config.xml holds the rows, installed or not.
     * @param \SimpleXMLElement|null $root the configuration's root, config.xml's by default
     * @return array uuid => label, sorted by label
     */
    public static function rowLabels($root = null)
    {
        $root = $root ?? Config::getInstance()->object();
        $found = [];
        if (!isset($root->OPNsense->UserIdentity)) {
            return $found;
        }
        $identity = $root->OPNsense->UserIdentity;
        foreach ([['groups', 'group'], ['users', 'user']] as $where) {
            list($list, $item) = $where;
            if (!isset($identity->$list->$item)) {
                continue;
            }
            foreach ($identity->$list->$item as $row) {
                $uuid = (string)$row['uuid'];
                $name = self::plain($row->name ?? '', 128);
                if (!preg_match(self::UUID, $uuid) || $name === '') {
                    continue;
                }
                $alias = self::plain($row->alias ?? '', 64);
                $label = $item === 'group' ?
                    self::fill(gettext('%s (a group, %s)'), '%s (a group, %s)', $name, $alias) :
                    self::fill(gettext('%s (a user, %s)'), '%s (a user, %s)', $name, $alias);
                if ((string)($row->enabled ?? '1') === '0') {
                    $label = self::fill(gettext('%s - switched off in User Identity'), '%s - switched off in User Identity', $label);
                }
                $found[strtolower($uuid)] = $label;
            }
        }
        natcasesort($found);
        return $found;
    }

    protected function actionPostLoadingEvent()
    {
        if (self::$cache === null) {
            $installed = Sources::installed()['identity'];
            $labels = self::rowLabels();
            /* what is offered, and the rows a removal left, for the values saved before it */
            self::$cache = [$installed ? $labels : [], $installed ? [] : $labels];
        }
        list($options, $left) = self::$cache;
        /* a row saved that User Identity holds no more, or that it left behind when it was removed: kept,
           marked, so it is neither hidden nor dropped */
        foreach (explode(',', (string)$this->internalValue) as $uuid) {
            if ($uuid === '' || isset($options[$uuid]) || !preg_match(self::UUID, $uuid)) {
                continue;
            }
            $options[$uuid] = isset($left[$uuid]) ?
                self::fill(gettext('%s - User Identity is not installed'), '%s - User Identity is not installed', $left[$uuid]) :
                self::fill(gettext('%s (not in User Identity now)'), '%s (not in User Identity now)', $uuid);
        }
        $this->internalOptionList = $options;
    }
}
