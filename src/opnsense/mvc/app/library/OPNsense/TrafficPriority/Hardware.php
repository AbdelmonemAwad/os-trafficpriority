<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\TrafficPriority;

/**
 * Which classes have a place in an XGS appliance's switch queues - decided here, at every filter
 * reload, and written into the rules file as the rules that take each place's DSCP off other traffic;
 * scripts/trafficpriority/apply.py gives the switch the DSCPs those rules name, and nothing else. The
 * model refuses at the save a minimum this would not hold.
 *
 * Two TCAM entries are free in the switch (os-xgs-npu's switch_qos.py), so two DSCPs at most have a
 * queue of their own: those of the classes switched on that make rules (Marking::problem() none), in
 * the page's order - by sequence, then as listed - a DSCP of Best Effort (0) or below it (CS1, and LE,
 * 1) left out, and so is a class marking IPv6 alone, the switch's key being IPv4's.
 *
 * THE SWITCH QUEUES EVERY FRAME OF A DSCP, not a class's connections: its entry picks out every frame
 * leaving the coprocessor with that DSCP, whoever marked it - a computer marking its own traffic EF, a
 * download arriving with EF. So for each place's DSCP a rule comes first that sets the DSCP to 0 on
 * every connection opening with it, on every interface, both ways; the classes' own rules come after
 * it and mark their connections again - of two match rules pf keeps the last one's mark (pf.c:5039-5056)
 * - so that only the classes' connections carry the DSCP. pf fixes a connection's mark when it opens:
 * a connection that opens without the DSCP and whose replies carry it keeps it on the way back.
 *
 * A minimum is held by the switch's weighted queues: only on a class with a place; the minimums of
 * the classes switched on add up to 100 at most; and not beside a class with a place and no minimum,
 * which would be strict and go before it - every class with a place has a minimum, or none has.
 */
class Hardware
{
    const PLACES = 2;
    /* Best Effort, and the DSCPs below it: LE (1, RFC 8622) and CS1 */
    const BELOW = [0 => 'best-effort', 1 => 'below-default', 8 => 'below-default'];
    /* each place's rule: this, then the DSCP */
    const LABEL = 'trafficpriority-clear-';
    /* os-xgs-npu's switch tool, and the one model it writes on: the XGS 3300 */
    const TOOL = '/usr/local/opnsense/scripts/xgs/switch_qos.py';
    const WRITES = 'AMDA0202-0004';

    /* stand-ins for the tests: whether the tool is there (bool), and the planar serial (string) */
    public static $tool = null;
    public static $serial = null;

    /**
     * Whether the switch takes this plugin's queues here: os-xgs-npu's switch tool installed, on the
     * XGS 3300 (the planar serial carries the assembly number; switch_qos.py's WRITES).
     */
    public static function switchInUse()
    {
        $tool = self::$tool ?? is_file(self::TOOL);
        if (!$tool) {
            return false;
        }
        $serial = self::$serial;
        if ($serial === null) {
            $serial = trim((string)@shell_exec('/bin/kenv -q smbios.planar.serial 2>/dev/null'));
        }
        return strpos((string)$serial, self::WRITES) !== false;
    }

    /**
     * A minimum as the model stores it, 1 to 100; null for none or one that is not.
     */
    public static function minimum($value)
    {
        $value = trim((string)$value);
        if (!preg_match('/^[0-9]{1,3}$/D', $value) || (int)$value < 1 || (int)$value > 100) {
            return null;
        }
        return (int)$value;
    }

    /**
     * The classes switched on, as the page shows them: by sequence, then as listed (uuid => fields).
     */
    public static function ordered(array $classes)
    {
        $on = [];
        $index = 0;
        foreach ($classes as $uuid => $class) {
            if (($class['enabled'] ?? '1') === '1') {
                $on[] = [Marking::sequence($class['sequence'] ?? ''), $index, $uuid];
            }
            $index++;
        }
        sort($on);
        $out = [];
        foreach ($on as $item) {
            $out[$item[2]] = $classes[$item[2]];
        }
        return $out;
    }

    /**
     * Each class's place: 'hardware', 'third' (both places taken), 'best-effort', 'below-default',
     * 'ipv6', 'rule' (it makes no rule: Marking::problem()) or 'off'; uuid => word.
     */
    public static function places(array $classes)
    {
        $why = [];
        foreach ($classes as $uuid => $class) {
            $why[$uuid] = 'off';
        }
        $taken = [];
        foreach (self::ordered($classes) as $uuid => $class) {
            $dscp = Marking::dscp($class['dscp'] ?? '');
            if (Marking::problem($class, (string)$uuid) !== null) {
                $why[$uuid] = 'rule';
            } elseif (isset(self::BELOW[$dscp])) {
                $why[$uuid] = self::BELOW[$dscp];
            } elseif (($class['ipprotocol'] ?? 'inet') === 'inet6') {
                $why[$uuid] = 'ipv6';
            } elseif (in_array($dscp, $taken, true)) {
                $why[$uuid] = 'hardware';
            } elseif (count($taken) < self::PLACES) {
                $taken[] = $dscp;
                $why[$uuid] = 'hardware';
            } else {
                $why[$uuid] = 'third';
            }
        }
        return $why;
    }

    /**
     * The DSCPs that have a place, in order.
     */
    public static function dscps(array $classes)
    {
        $out = [];
        foreach (self::places($classes) as $uuid => $why) {
            $dscp = Marking::dscp($classes[$uuid]['dscp'] ?? '');
            if ($why === 'hardware' && !in_array($dscp, $out, true)) {
                $out[] = $dscp;
            }
        }
        return $out;
    }

    /**
     * The minimums of the classes with a place, added up.
     */
    public static function total(array $classes)
    {
        $sum = 0;
        foreach (self::places($classes) as $uuid => $why) {
            $minimum = self::minimum($classes[$uuid]['minimum'] ?? '');
            if ($minimum !== null && $why === 'hardware') {
                $sum += $minimum;
            }
        }
        return $sum;
    }

    /**
     * Whether a class with a minimum and one without both have a place: the one without would be
     * strict and go before the other, which then keeps no minimum.
     */
    public static function mixed(array $classes)
    {
        $with = $without = false;
        foreach (self::places($classes) as $uuid => $why) {
            if ($why !== 'hardware') {
                continue;
            }
            if (self::minimum($classes[$uuid]['minimum'] ?? '') !== null) {
                $with = true;
            } else {
                $without = true;
            }
        }
        return $with && $without;
    }

    /**
     * The rules that take each place's DSCP off other traffic, as registerFilterRule() takes them, in
     * the places' order: a match rule on every interface where connections come in, IPv4 - the switch's
     * key - opening with the DSCP, which sets it to 0, both ways. Registered before every class's rule,
     * whose mark then comes after it. $key is Marking::markKey()'s.
     */
    public static function clearing(array $dscps, $key)
    {
        if (!in_array($key, ['scrub', 'dn'], true)) {
            return [];
        }
        $rules = [];
        foreach ($dscps as $dscp) {
            $mark = 'set-tos ' . Marking::tos(0);
            $rules[] = [
                'type' => 'match',
                'direction' => 'in',
                'quick' => false,
                'disablereplyto' => true,
                'ipprotocol' => 'inet',
                'tos' => Marking::tos($dscp),
                $key => $key === 'scrub' ? $mark : 'scrub ( ' . $mark . ' )',
                'label' => self::LABEL . $dscp,
                'descr' => Marking::DESCR . sprintf('DSCP %d taken off other traffic', $dscp),
            ];
        }
        return $rules;
    }
}
