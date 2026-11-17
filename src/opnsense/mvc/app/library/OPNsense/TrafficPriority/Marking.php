<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\TrafficPriority;

use OPNsense\Firewall\FilterRule;
use OPNsense\Firewall\Util;

/**
 * What one class of Traffic Priority becomes in pf, and why a class can become nothing. The rules hook
 * (plugins.inc.d/trafficpriority.inc) registers what rules() returns, the model (TrafficPriority.php)
 * refuses at the save a class problem() refuses, and the page's Applied tab says problem()'s answer -
 * one place for the three, so they cannot disagree.
 *
 * A class is one pf `match` rule for each interface, IP version and pair of addresses it is written
 * for, read where connections come in, which sets the class's DSCP:
 *
 *   match in on igb1 inet proto udp from {any} to {any} port {5060} scrub ( set-tos 0xb8 )
 *       label "trafficpriority-<the class's UUID>" # Traffic Priority: Voice
 *
 * OPNsense 26.7 is FreeBSD 15.1; the pf facts below are read in its source, opnsense/src stable/26.7 at
 * 1633399de9dd (its head on 2026-11-17), and OPNsense's in opnsense/core 26.7.3 unless another version
 * is named.
 *
 *  - A match rule decides nothing. pf applies its actions to the packet and goes on to the next rule
 *    (pf.c:5836-5867); the owner's rules still pass or block. It is never quick: pf stops at a quick
 *    rule that matches, a match rule too (pf.c:5891), and then no rule of the owner's would decide.
 *    OPNsense writes every rule quick unless told otherwise (FilterRule.php:220-223).
 *  - Priority 0 puts the classes before every rule OPNsense writes (its own begin at 1,
 *    filter.lib.inc:209-222; the owner's at 400000 and up, Rule.php:486-497): a quick rule that
 *    matched first would leave them unread. Only the antispoof lines come before them, which are not
 *    quick (filter.inc:386-389, 629-648).
 *  - The mark goes with the connection, both ways. The state the owner's pass rule makes takes the
 *    actions of every match rule that matched (pf.c:5867, 6274), and every packet of the state, either
 *    way, is given them (pf.c:11389, 11401), the DSCP written and the two ECN bits kept
 *    (pf_norm.c:2245-2262). It is fixed when the state is made: a class changed reaches new connections.
 *    os-xgs-npu's drivers read the same state field (act.set_tos) to put the mark on a connection in
 *    hardware, measured with a normalization rule (os-xgs-npu: docs/measurements/flow-dscp-2026-10-24.md).
 *  - Not a normalization rule, the way that measurement set it. A plugin cannot add one: OPNsense writes
 *    the owner's own and nothing else there (filter.inc:468-546). And pf reads those rules at the IP
 *    header first without their ports, the first that matches setting its mark (pf_norm.c:1167-1203,
 *    1321-1354), so one with a port and a DSCP marks every connection matching the rest of it, its
 *    port aside - read in the source, not measured. A match rule checks its ports (pf.c:5763-5770).
 *  - The mark is written `scrub ( set-tos 0xNN )`, which pfctl takes on a filter rule
 *    (parse.y:2932-2948, 1516-1522, 7695-7698), NN the DSCP shifted by two, as the TOS byte holds it.
 */
class Marking
{
    /* registerFilterRule()'s priority for every rule of every class */
    const PRIORITY = 0;
    /* each rule's label: this, then its class's UUID - the page counts a class's rules by it */
    const LABEL = 'trafficpriority-';
    /* each rule's description, before the class's own */
    const DESCR = 'Traffic Priority: ';
    /* the protocols a port may be given for: pfctl refuses a port on any other (parse.y:5309), and
       with it the whole rule set */
    const PORT_PROTOCOLS = ['tcp', 'udp', 'tcp/udp'];
    /* a class whose sequence cannot be read is applied before every other, so any other wins */
    const NO_SEQUENCE = 100000;

    /* where log() writes: the system log, or what a test puts here, function ($priority, $message) */
    public static $log = null;

    /**
     * A line for the system log, as the rules hook says what it left out and why.
     */
    public static function log($priority, $message)
    {
        if (is_callable(self::$log)) {
            call_user_func(self::$log, $priority, $message);
            return;
        }
        syslog($priority, $message);
    }

    /**
     * The classes of config.xml as OPNsense's legacy array has them (Config.php's toArray(): one class
     * is an array of its fields, several a list of them, the UUID in '@attributes'), by UUID, in their
     * order there, each field a string.
     * @param mixed $node $config['OPNsense']['TrafficPriority']['classes']['class']
     * @return array
     */
    public static function classes($node)
    {
        if (!is_array($node)) {
            return [];
        }
        $out = [];
        foreach (array_is_list($node) ? $node : [$node] as $class) {
            if (!is_array($class)) {
                continue;
            }
            $uuid = (string)($class['@attributes']['uuid'] ?? '');
            $fields = [];
            foreach ($class as $name => $value) {
                if (is_string($value)) {
                    $fields[$name] = $value;
                }
            }
            $out[$uuid] = $fields;
        }
        return $out;
    }

    /**
     * A DSCP as the model stores it, 0 to 63; null for anything else.
     */
    public static function dscp($value)
    {
        $value = trim((string)$value);
        if (!preg_match('/^[0-9]{1,2}$/', $value) || (int)$value > 63) {
            return null;
        }
        return (int)$value;
    }

    /**
     * The TOS byte pf takes for a DSCP: the DSCP in its six high bits, the two ECN bits clear, so the
     * mark leaves a packet's ECN as it came (pf_norm.c:2251) and os-xgs-npu's fast path can carry it -
     * a mark with ECN bits it keeps with the host (os-xgs-npu: flow-dscp-2026-10-24.md, "ECN is kept").
     */
    public static function tos($dscp)
    {
        return sprintf('0x%02x', ((int)$dscp & 0x3f) << 2);
    }

    /**
     * FilterRule's protocol for the model's: '' for any, null for one this does not know.
     */
    public static function protocol($value)
    {
        $value = strtolower(trim((string)$value));
        if ($value === '' || $value === 'any') {
            return '';
        }
        return in_array($value, self::PORT_PROTOCOLS, true) ? $value : null;
    }

    /**
     * A port field as FilterRule takes it: '' for none, which any is too (Rule.php:111-112 drops it).
     */
    public static function port($value)
    {
        $value = trim((string)$value);
        return $value === 'any' ? '' : $value;
    }

    /**
     * The IP versions of the model's choice, as pf names them.
     */
    public static function families($ipprotocol)
    {
        switch ((string)$ipprotocol) {
            case 'inet':
                return ['inet'];
            case 'inet6':
                return ['inet6'];
            case 'inet46':
                return ['inet', 'inet6'];
        }
        return [];
    }

    /**
     * 'inet' or 'inet6' for an address or a network written out; null for a name, which pf resolves
     * for either version itself.
     */
    public static function family($address)
    {
        $address = (string)$address;
        if (Util::isIpAddress($address) || Util::isSubnet($address)) {
            return strpos($address, ':') === false ? 'inet' : 'inet6';
        }
        return null;
    }

    /**
     * The addresses of a source or destination field, comma-separated as NetworkAliasField keeps them:
     * ['any'] when it is empty or one of them is any; null when one is neither an address, a network
     * nor a name - an alias, an interface's network (lan) or address (lanip), or (self). Such a one is
     * never passed on: OPNsense's Rule takes a field that PHP's empty() calls empty, "0" among them, for
     * any address (Rule.php:273), which would widen the class.
     */
    public static function addresses($value)
    {
        $items = [];
        foreach (explode(',', (string)$value) as $item) {
            $item = trim($item);
            if ($item === '') {
                continue;
            }
            if ($item !== 'any' && self::family($item) === null && !preg_match('/^(\(self\)|[A-Za-z_][A-Za-z0-9_]*)$/', $item)) {
                return null;
            }
            $items[] = $item;
        }
        return empty($items) || in_array('any', $items, true) ? ['any'] : array_values(array_unique($items));
    }

    /**
     * The interfaces, as FilterRule's 'interface' takes them: OPNsense's names for them, separated by
     * commas, a rule each (Rule.php:271); '' for every interface, which only an empty field is. null
     * when the field holds something that is not a name: an empty element ("lan,,opt1") or "0" is taken
     * by Rule for no interface, a rule on every interface (Rule.php:271, 402-413), so such a class is
     * not written rather than widened.
     */
    public static function interfaces($value)
    {
        $value = (string)$value;
        if ($value === '') {
            return '';
        }
        $names = explode(',', $value);
        foreach ($names as $name) {
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_.]*$/', $name)) {
                return null;
            }
        }
        return implode(',', array_values(array_unique($names)));
    }

    /**
     * The label of a class's rules; null when its ID is not a UUID.
     */
    public static function label($uuid)
    {
        $uuid = strtolower((string)$uuid);
        if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $uuid)) {
            return null;
        }
        return self::LABEL . $uuid;
    }

    /**
     * Every source, destination and IP version a class can be written for: an address or a network
     * written out keeps its own version, and a source of one version with a destination of the other is
     * no rule at all - pfctl refuses such a rule (parse.y:6346-6351, 6533), and with it the whole rule
     * set, every rule of the owner's too. A name fits both versions. Any is ''.
     * @return array of [source, destination, 'inet' or 'inet6']
     */
    public static function combinations($sources, $destinations, $ipprotocol)
    {
        $from = self::addresses($sources);
        $to = self::addresses($destinations);
        if ($from === null || $to === null) {
            return [];
        }
        $out = [];
        foreach ($from as $src) {
            foreach ($to as $dst) {
                foreach (self::families($ipprotocol) as $family) {
                    $fs = $src === 'any' ? null : self::family($src);
                    $fd = $dst === 'any' ? null : self::family($dst);
                    if (($fs !== null && $fs !== $family) || ($fd !== null && $fd !== $family)) {
                        continue;
                    }
                    $out[] = [$src === 'any' ? '' : $src, $dst === 'any' ? '' : $dst, $family];
                }
            }
        }
        return $out;
    }

    /**
     * Why a class makes no rule, one word the page turns into a sentence; null when it makes some.
     *   id         its ID is not a UUID (config.xml written by other means)
     *   dscp       the DSCP to set is not one of 0 to 63
     *   match      the DSCP to match is not one of 1 to 63: pf cannot match 0, which it takes for no
     *              DSCP asked (pf.c:5805, "r->tos &&")
     *   protocol   a protocol this does not know
     *   ports      a port without TCP or UDP
     *   interface  an interface field that names none
     *   address    an address field that names none
     *   family     no source, destination and IP version fit together
     */
    public static function problem(array $class, $uuid)
    {
        if (self::label($uuid) === null) {
            return 'id';
        }
        if (self::dscp($class['dscp'] ?? '') === null) {
            return 'dscp';
        }
        $match = trim((string)($class['match_dscp'] ?? ''));
        if ($match !== '' && !self::dscp($match)) {
            return 'match';
        }
        $protocol = self::protocol($class['protocol'] ?? '');
        if ($protocol === null) {
            return 'protocol';
        }
        $ports = self::port($class['source_port'] ?? '') . self::port($class['destination_port'] ?? '');
        if ($ports !== '' && !in_array($protocol, self::PORT_PROTOCOLS, true)) {
            return 'ports';
        }
        if (self::interfaces($class['interface'] ?? '') === null) {
            return 'interface';
        }
        if (self::addresses($class['source_net'] ?? '') === null || self::addresses($class['destination_net'] ?? '') === null) {
            return 'address';
        }
        if (empty(self::combinations($class['source_net'] ?? '', $class['destination_net'] ?? '', $class['ipprotocol'] ?? ''))) {
            return 'family';
        }
        return null;
    }

    /**
     * The rules of one class, as OPNsense's registerFilterRule() takes them; none when problem() says
     * why. $key is markKey()'s: the FilterRule key that writes the mark on this OPNsense.
     */
    public static function rules(array $class, $uuid, $key)
    {
        if (self::problem($class, $uuid) !== null || !in_array($key, ['scrub', 'dn'], true)) {
            return [];
        }
        $mark = 'set-tos ' . self::tos(self::dscp($class['dscp']));
        $base = [
            'type' => 'match',
            'direction' => 'in',
            'quick' => false,
            /* a match rule takes no reply-to (parse.y:5386); FilterRule would add one on an
               interface with a gateway (FilterRule.php:157), then drop it and log that it did */
            'disablereplyto' => true,
            $key => $key === 'scrub' ? $mark : 'scrub ( ' . $mark . ' )',
            'label' => self::label($uuid),
            'descr' => self::DESCR . preg_replace('/[\r\n]+/', ' ', (string)($class['description'] ?? '')),
        ];
        $interfaces = self::interfaces($class['interface'] ?? '');
        if ($interfaces !== '') {
            $base['interface'] = $interfaces;
        }
        $protocol = self::protocol($class['protocol'] ?? '');
        if ($protocol !== '') {
            $base['protocol'] = $protocol;
        }
        foreach (['source_port' => 'from_port', 'destination_port' => 'to_port'] as $field => $port) {
            $value = self::port($class[$field] ?? '');
            if ($value !== '') {
                $base[$port] = $value;
            }
        }
        $match = trim((string)($class['match_dscp'] ?? ''));
        if ($match !== '') {
            $base['tos'] = self::tos(self::dscp($match));
        }
        $rules = [];
        foreach (self::combinations($class['source_net'] ?? '', $class['destination_net'] ?? '', $class['ipprotocol'] ?? '') as $pair) {
            $rule = $base;
            $rule['ipprotocol'] = $pair[2];
            if ($pair[0] !== '') {
                $rule['from'] = $pair[0];
            }
            if ($pair[1] !== '') {
                $rule['to'] = $pair[1];
            }
            $rules[] = $rule;
        }
        return $rules;
    }

    /**
     * A class's sequence; NO_SEQUENCE when it cannot be read.
     */
    public static function sequence($value)
    {
        $value = trim((string)$value);
        return ctype_digit($value) ? (int)$value : self::NO_SEQUENCE;
    }

    /**
     * The classes in the order they are registered: the highest sequence first, so that the lowest -
     * registered last - is the last match rule pf applies to a connection, and its DSCP the one the
     * connection keeps (pf_rule_to_actions() sets each matching rule's in turn, pf.c:5039-5056, 5867).
     * Of two with the same sequence, the one first in the list goes last, and wins.
     */
    public static function ordered(array $classes)
    {
        $keys = array_keys($classes);
        $index = array_flip($keys);
        usort($keys, function ($a, $b) use ($classes, $index) {
            return [self::sequence($classes[$b]['sequence'] ?? ''), $index[$b]]
                <=> [self::sequence($classes[$a]['sequence'] ?? ''), $index[$a]];
        });
        $out = [];
        foreach ($keys as $key) {
            $out[$key] = $classes[$key];
        }
        return $out;
    }

    /**
     * The FilterRule key that writes the mark on this OPNsense, read from its own FilterRule's table of
     * keys without making a rule (a FilterRule made here first would fill the class's address map
     * without the interfaces, Rule.php:48-67): 'scrub', where it writes `scrub ( ... )` (26.7.9,
     * FilterRule.php:58 and 114-117 there); else 'dn', which 26.7 to 26.7.8 write as given
     * (FilterRule.php:69, Rule.php:211-217) and set themselves only from a Shaper rule's pipe or queue
     * (FilterRule.php:315-333) - a carrier for the text only: Firewall: Shaper is not read or written.
     * null when neither is there: no rule then, rather than one pfctl refuses, which keeps the whole rule
     * set from loading (filter.inc:399-437).
     * @param array|null $procorder a FilterRule's table of keys; null: OPNsense's own
     */
    public static function markKey($procorder = null)
    {
        $has = false;
        if ($procorder === null) {
            $procorder = (new \ReflectionClass(FilterRule::class))->getDefaultProperties()['procorder'] ?? [];
            $has = method_exists(FilterRule::class, 'parseScrub');
        } else {
            $has = ($procorder['scrub'] ?? '') === 'parseScrub';
        }
        if (!is_array($procorder)) {
            return null;
        }
        if (($procorder['scrub'] ?? '') === 'parseScrub' && $has) {
            return 'scrub';
        }
        if (($procorder['dn'] ?? '') === 'parsePlain') {
            return 'dn';
        }
        return null;
    }
}
