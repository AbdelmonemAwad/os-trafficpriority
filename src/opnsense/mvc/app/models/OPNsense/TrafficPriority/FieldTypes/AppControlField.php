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
 * The applications of os-appcontrol a class takes (svc-2-12) - or, with <Kind>category</Kind>, its
 * categories (top-08): those Application Control keeps a pf table for now, its own aliases in Firewall:
 * Aliases (OPNsense\TrafficPriority\Sources::appTables()), each by the name nDPI gives it - the key
 * os-appcontrol's own settings keep - and labelled with it. Application Control makes a table for every
 * category of the installed nDPI while it classifies, and one for each application chosen there - in its
 * Application tables, Blocked applications or Rules - at its Apply. Read from the configuration, not
 * through os-appcontrol's model, so the field loads where os-appcontrol is not installed: it then offers
 * nothing, and the page says why. A table switched off there is offered, marked so - a class takes
 * nothing through it while it is off. A name saved that no table holds now stays an option, marked so,
 * rather than vanish from the field and from the next save; the rules hook takes no table by it. A value
 * that is not an option fails the model's validation, as an OptionField's does.
 */
class AppControlField extends BaseListField
{
    private static $cache = [];
    private $kind = 'application';

    /**
     * application (the default) or category
     */
    public function setKind($value)
    {
        $this->kind = trim((string)$value) === 'category' ? 'category' : 'application';
    }

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
     * a name as an option may show it: no control characters, no < or >
     */
    private static function plain($text)
    {
        return trim(preg_replace('/[^\x20-\x7e\x{a0}-\x{ffff}]/u', '', str_replace(['<', '>'], ' ', (string)$text)) ?? '');
    }

    /**
     * @param string $kind application or category
     * @param \SimpleXMLElement|null $root the configuration's root, config.xml's by default
     * @return array name => label, sorted by label
     */
    public static function nameOptions($kind, $root = null)
    {
        $root = $root ?? Config::getInstance()->object();
        $aliases = [];
        if (isset($root->OPNsense->Firewall->Alias->aliases->alias)) {
            foreach ($root->OPNsense->Firewall->Alias->aliases->alias as $alias) {
                $aliases[] = [
                    'name' => trim((string)($alias->name ?? '')),
                    'type' => trim((string)($alias->type ?? '')),
                    'enabled' => trim((string)($alias->enabled ?? '1')) === '1',
                    'description' => (string)($alias->description ?? ''),
                ];
            }
        }
        $found = [];
        foreach (Sources::appTables($aliases, $kind) as $name => $table) {
            $label = self::plain($name);
            if ($label === '' || $label !== $name || strpos($name, ',') !== false) {
                /* a name a list field could not hold, or not show as it is: not offered */
                continue;
            }
            if (!$table['enabled']) {
                $label = self::fill(gettext('%s - switched off in Application Control'), '%s - switched off in Application Control', $label);
            }
            $found[$name] = $label;
        }
        natcasesort($found);
        return $found;
    }

    protected function actionPostLoadingEvent()
    {
        if (!isset(self::$cache[$this->kind])) {
            self::$cache[$this->kind] = self::nameOptions($this->kind);
        }
        $options = self::$cache[$this->kind];
        /* a name saved that Application Control keeps no table for now: kept, marked, neither hidden nor dropped */
        foreach (explode(',', (string)$this->internalValue) as $name) {
            if ($name !== '' && !isset($options[$name]) && self::plain($name) === $name) {
                $options[$name] = self::fill(gettext('%s (no table in Application Control now)'),
                    '%s (no table in Application Control now)', $name);
            }
        }
        $this->internalOptionList = $options;
    }
}
