<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\TrafficPriority;

/**
 * Which classes have a place in the switch's queues on an XGS appliance, for the model's refusals of a
 * minimum at the save - the same order and the same test as scripts/trafficpriority/hardware.py,
 * which decides what the switch is given (tools/test-mvc.php and tools/test-hardware.py hold the two
 * to the same cases).
 *
 * Two TCAM entries are free in the switch (os-xgs-npu's switch_qos.py), so two DSCPs at most have a
 * queue of their own: those of the classes switched on, in the page's order - by sequence, then as
 * listed - a DSCP of Best Effort (0) or of a class marking IPv6 alone left out, the switch's key being
 * IPv4's. A minimum is held by the switch's weighted queues, so only on a class with a place, and the
 * minimums of the classes switched on add up to 100 at most.
 */
class Hardware
{
    const PLACES = 2;

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
     * Each class's place: 'hardware', 'third' (both places taken), 'best-effort', 'ipv6', 'dscp' (not
     * readable) or 'off'; uuid => word.
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
            if ($dscp === null) {
                $why[$uuid] = 'dscp';
            } elseif ($dscp === 0) {
                $why[$uuid] = 'best-effort';
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
     * The minimums of the classes switched on that have a place, added up.
     */
    public static function total(array $classes)
    {
        $places = self::places($classes);
        $sum = 0;
        foreach (self::ordered($classes) as $uuid => $class) {
            $minimum = self::minimum($class['minimum'] ?? '');
            if ($minimum !== null && $places[$uuid] === 'hardware') {
                $sum += $minimum;
            }
        }
        return $sum;
    }
}
