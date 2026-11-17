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
 * A hook that throws stops the filter reload: OPNsense calls it with nothing around it
 * (plugins.inc:244-259), and the reload is what loads every rule of the owner's. So nothing here may
 * throw: whatever goes wrong is said in the system log, and the reload goes on without the class it
 * concerns.
 */

use OPNsense\Firewall\Plugin;
use OPNsense\TrafficPriority\Marking;

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
        $classes = Marking::ordered($classes);
    } catch (\Throwable $e) {
        syslog(LOG_ERR, 'Traffic Priority: no class applied: ' . $e->getMessage());
        return;
    }

    foreach ($classes as $uuid => $class) {
        $name = preg_replace('/[\r\n]+/', ' ', (string)($class['description'] ?? ''));
        try {
            $rules = Marking::rules($class, (string)$uuid, $key);
            if (empty($rules)) {
                Marking::log(LOG_WARNING, sprintf('Traffic Priority: class "%s" makes no rule (%s)', $name,
                    Marking::problem($class, (string)$uuid) ?? 'unknown'));
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
