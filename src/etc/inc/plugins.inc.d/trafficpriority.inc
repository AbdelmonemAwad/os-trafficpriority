<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The classes' rules, registered at every filter reload from config.xml - the way os-blocklists
 * registers its own. They are never among the owner's rules in Firewall: Rules, so turning Traffic
 * Priority off or removing it leaves nothing behind there; Firewall: Shaper and Firewall: Settings:
 * Normalization are neither read nor written.
 *
 * Each class switched on is one pf match rule for each interface, IP version and pair of addresses it
 * names, read where connections come in, which sets the class's DSCP on them, both ways
 * (OPNsense\TrafficPriority\Marking says what the rule is and why it is so). Off by default: nothing
 * is registered until Enabled is on and a class is applied.
 *
 * On an XGS 3300 whose switch os-xgs-npu sets, while a class has a place in the switch's queues
 * (OPNsense\TrafficPriority\Hardware), every IPv4 connection's DSCP is first set to 0, both ways - the
 * switch queues every frame by its DSCP, whoever marked it - by one rule, registered before every
 * class's rule, so that the classes' own marks come after it and are the ones their connections keep.
 *
 * A class that names groups and users of os-useridentity, or applications and categories of
 * os-appcontrol, takes their pf tables as its source or destination, as config.xml holds them at this
 * reload (OPNsense\TrafficPriority\Sources) - and makes no rule while one side has none, which the
 * system log says. Neither plugin's settings or tables are written here.
 *
 * A hook that throws stops the filter reload: OPNsense calls it with nothing around it
 * (plugins.inc:244-259), and the reload is what loads every rule of the owner's. So nothing here may
 * throw: whatever goes wrong is said in the system log, and the reload goes on without the class it
 * concerns.
 */

use OPNsense\Firewall\Plugin;
use OPNsense\TrafficPriority\Hardware;
use OPNsense\TrafficPriority\Marking;
use OPNsense\TrafficPriority\Sources;

function trafficpriority_firewall(Plugin $fw)
{
    global $config;

    try {
        $own = $config['OPNsense']['TrafficPriority'] ?? [];
        if (!is_array($own) || (($own['general']['enabled'] ?? '0') !== '1')) {
            return;
        }
        $classes = array_filter(Marking::classes($own['classes']['class'] ?? []), function ($class) {
            return ($class['enabled'] ?? '1') === '1';
        });
        if (empty($classes)) {
            return;
        }
        $key = Marking::markKey();
        if ($key === null) {
            Marking::log(LOG_ERR, 'Traffic Priority: this OPNsense\'s FilterRule writes no pf scrub option; no class applied');
            return;
        }
        $clearing = Hardware::switchInUse() ? Hardware::clearing(Hardware::dscps($classes), $key) : [];
        $classes = Marking::ordered($classes);
    } catch (\Throwable $e) {
        syslog(LOG_ERR, 'Traffic Priority: no class applied: ' . $e->getMessage());
        return;
    }

    /* the other plugins' tables as config.xml holds them now, read once for every class; none when they
       cannot be read, so a class that names them makes no rule and every other is written as before */
    try {
        $aliases = Sources::aliases($config);
        $rows = Sources::rows($config);
        $plugins = Sources::plugins($config);
    } catch (\Throwable $e) {
        Marking::log(LOG_ERR, 'Traffic Priority: the tables of User Identity and Application Control not read: ' .
            $e->getMessage());
        $aliases = $rows = [];
        $plugins = ['identity' => null, 'appcontrol' => null];
    }

    /* while a class has a place, every IPv4 connection's DSCP set to 0 first; the classes' marks after it */
    foreach ($clearing as $rule) {
        try {
            $fw->registerFilterRule(Marking::PRIORITY, $rule);
        } catch (\Throwable $e) {
            Marking::log(LOG_ERR, sprintf('Traffic Priority: "%s" left out of this filter reload: %s', $rule['descr'],
                $e->getMessage()));
        }
    }

    foreach ($classes as $uuid => $class) {
        $name = preg_replace('/[\r\n]+/', ' ', (string)($class['description'] ?? ''));
        try {
            $tables = Sources::resolve($class, $aliases, $rows, $plugins);
            $rules = Marking::rules($class, (string)$uuid, $key, $tables);
            if (empty($rules)) {
                $why = Marking::problem($class, (string)$uuid);
                if ($why === null && Sources::idle($tables)) {
                    /* the side with no table, and the first reason the page gives of it */
                    $users = $tables['from'] !== null && empty($tables['from']);
                    $first = '';
                    foreach ($tables['items'] as $item) {
                        if (in_array($item['kind'], $users ? ['group', 'user'] : ['application', 'category'], true)) {
                            $first = $item['why'];
                            break;
                        }
                    }
                    $why = sprintf('no table for its %s now: %s', $users ? 'groups and users' : 'applications and categories', $first);
                }
                Marking::log(LOG_WARNING, sprintf('Traffic Priority: class "%s" makes no rule (%s)', $name, $why ?? 'unknown'));
                continue;
            }
            foreach ($rules as $rule) {
                $fw->registerFilterRule(Marking::PRIORITY, $rule);
            }
        } catch (\Throwable $e) {
            Marking::log(LOG_ERR, sprintf('Traffic Priority: class "%s" left out of this filter reload: %s', $name,
                $e->getMessage()));
        }
    }
}
