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
 *  - Nothing goes into /tmp/rules.debug that would break it. pfctl refuses the whole rule set for one
 *    line it cannot read (filter.inc:399-437), and OPNsense writes some fields as they are given: a
 *    port it cannot map into a '#debug:' comment and into the rule it comments out (Rule.php:103-130,
 *    355), the description at the end of the line (Rule.php:171-174). config.xml can be written by
 *    other means than the page, so each field is taken here only in a form that cannot break a line
 *    or the grammar - a class with another is not written, and problem() says which field.
 *  - A class narrows what it marks: an interface, a source, a destination, a port or a DSCP to
 *    arrive with - or groups and users, applications or categories. One with none of them would mark
 *    every connection, both ways, every download with them; the page refuses it at the save, and it is
 *    not written (narrows()).
 *
 * GROUPS AND USERS, APPLICATIONS AND CATEGORIES (svc-2-12, top-08). A class may name groups and users of
 * os-useridentity, and applications and categories of os-appcontrol: their pf tables, which those
 * plugins make and fill, are the rule's source and destination (Sources resolves them at every filter
 * reload; neither plugin's settings or tables are written here):
 *
 *   match in on igb1 inet from $uid_staff to $appcontrol_Zoom scrub ( set-tos 0xb8 )
 *       label "trafficpriority-<the class's UUID>" # Traffic Priority: Calls
 *
 *  - Groups and users are where the connections come from: User Identity's tables hold the addresses it
 *    maps to them, their devices. They take the place of Source, which stays any (problem() 'sources'):
 *    pf ANDs nothing within a rule's source, and two sources would be read as either.
 *  - Applications and categories are where they go: Application Control's tables hold the servers nDPI
 *    named as them. They take the place of Destination likewise ('destinations').
 *  - Each table goes in as its alias, by name, and OPNsense's own Rule writes it as the alias's macro,
 *    $name (Rule.php:61-66, 87-93 in 26.7 and 26.7.9), which OPNsense defines in the rules file, with its
 *    table, for every alias of config.xml, switched on or not (filter_generate_aliases(),
 *    filter.inc:574-627: the table at 619, the macro at 621) - a name Rule does not know as an alias it
 *    writes commented out (Rule.php:94-98), so a rule never names a table pfctl is not given. Only the
 *    tables Sources finds the other plugin's own, External and switched on are written at all.
 *  - A class whose groups and users have no table now, or whose applications and categories have none,
 *    makes no rule - never one from every source or to every destination. The rules hook says so in the
 *    system log, and the page says why for each. It keeps its place in the switch (Hardware::places()),
 *    and the reload records that it left the class idle in the rules file itself, as a line pf never
 *    reads (idleRecord()), for apply.py to keep that place too.
 *  - pf fixes a connection's mark when it opens. A connection opened before its device's address joined
 *    a user's table, or before its server joined an application's, keeps the mark it opened with.
 */
class Marking
{
    /* registerFilterRule()'s priority for every rule of every class */
    const PRIORITY = 0;
    /* each rule's label: this, then its class's UUID - the page counts a class's rules by it */
    const LABEL = 'trafficpriority-';
    /* the label of the line recording a class a filter reload left idle: this, then its class's UUID */
    const IDLE_LABEL = 'trafficpriority-idle-';
    /* each rule's description, before the class's own */
    const DESCR = 'Traffic Priority: ';
    /* the protocols a port may be given for: pfctl refuses a port on any other (parse.y:5309), and
       with it the whole rule set */
    const PORT_PROTOCOLS = ['tcp', 'udp', 'tcp/udp'];
    /* a class whose sequence cannot be read is applied before every other, so any other wins */
    const NO_SEQUENCE = 100000;
    /* a class's fields, as config.xml and the model have them, and as problem() reads them */
    const FIELDS = ['enabled', 'sequence', 'description', 'interface', 'ipprotocol', 'protocol', 'source_net',
        'source_port', 'destination_net', 'destination_port', 'match_dscp', 'dscp', 'users', 'application',
        'categories'];

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
     * A port field as FilterRule takes it: '' for none, which any is too (Rule.php:111-112 drops it);
     * null for a value not taken here, whose class is then not written (problem(): 'port'). Taken: a
     * number from 1 to 65535; two of them joined by '-' or ':', the first not above the second - a
     * range; a name in lower case, as /etc/services has them; an alias's name - but not one of an alias
     * other than an alias of ports with ports in it. PortField refuses the rest at the save. In
     * config.xml written by other means: a value OPNsense cannot map is written as given into a
     * '#debug:' comment and into the rule it comments out (Rule.php:122-130, 355), and a line break in
     * it starts a line pf loads, ahead of every rule of the owner's. 26.7 to 26.7.7 write any alias as
     * `port $name` (Rule.php:115-121 there), and 26.7 to 26.7.5 a range in either order (Util::isPort()
     * there), and pfctl refuses an alias of addresses as a port, and a range whose first port is above
     * its second (parse.y:3836-3840, 5232) - with either, the whole rule set. The patterns end at the
     * end of the value ('D'): '$' alone also takes the place before a last line break.
     */
    public static function port($value)
    {
        $value = trim((string)$value);
        if ($value === '' || $value === 'any') {
            return '';
        }
        if (preg_match('/^[0-9]+([-:][0-9]+)?$/D', $value)) {
            $numbers = preg_split('/[-:]/', $value);
            foreach ($numbers as $number) {
                if (!preg_match('/^[1-9][0-9]{0,4}$/D', $number) || (int)$number > 65535) {
                    return null;
                }
            }
            return count($numbers) === 2 && (int)$numbers[0] > (int)$numbers[1] ? null : $value;
        }
        if (!preg_match('/^([a-z0-9][a-z0-9.+_-]*|[A-Za-z_][A-Za-z0-9_]{0,31})$/D', $value)) {
            return null;
        }
        return Util::isAlias($value) && !Util::isPortAlias($value) ? null : $value;
    }

    /**
     * A class's description as its rules carry it, after DESCR: a line break made a space, as OPNsense
     * drops it from its own comment (Rule.php:171-174). null when it ends in a backslash, spaces after
     * it aside, which FilterRule trims (Rule.php:350): pfctl takes a backslash at the end of a line as
     * joining the next line to it, a comment's too (parse.y:6806-6814, 6882-6883), so the next line of
     * /tmp/rules.debug - the class's next rule, or another class's - would not be loaded, and pf would
     * say nothing of it.
     */
    public static function description($value)
    {
        $text = preg_replace('/[\r\n]+/', ' ', (string)$value);
        return substr(rtrim($text), -1) === '\\' ? null : $text;
    }

    /**
     * Whether a class narrows what it marks: an interface, a source or a destination other than any, a
     * port, a DSCP it arrives with, or groups and users, applications or categories. One with none of
     * them would mark every connection that comes in on any interface, both ways - every download among
     * them - and upstream networks and Wi-Fi treat a mark such as EF as voice. The page refuses such a
     * class at the save; one written by other means is not written (problem(): 'everything'). Neither the
     * protocol nor the IP version counts. A class narrowed by tables alone makes no rule while it has none
     * (rules()), so it never marks more than they hold.
     */
    public static function narrows(array $class)
    {
        return self::interfaces($class['interface'] ?? '') !== ''
            || self::addresses($class['source_net'] ?? '') !== ['any']
            || self::addresses($class['destination_net'] ?? '') !== ['any']
            || self::port($class['source_port'] ?? '') !== ''
            || self::port($class['destination_port'] ?? '') !== ''
            || trim((string)($class['match_dscp'] ?? '')) !== ''
            || !empty(Sources::items($class['users'] ?? ''))
            || !empty(Sources::items($class['application'] ?? ''))
            || !empty(Sources::items($class['categories'] ?? ''));
    }

    /**
     * Whether a class names groups or users (their tables its source), and applications or categories
     * (theirs its destination): [names users, names applications or categories].
     */
    public static function tabled(array $class)
    {
        return [
            !empty(Sources::items($class['users'] ?? '')),
            !empty(Sources::items($class['application'] ?? '')) || !empty(Sources::items($class['categories'] ?? '')),
        ];
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
            if ($item !== 'any' && self::family($item) === null && !preg_match('/^(\(self\)|[A-Za-z_][A-Za-z0-9_]*)$/D', $item)) {
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
     * not written rather than widened. A name ends at the end of the field ('D'): a line break after
     * it is no name either.
     */
    public static function interfaces($value)
    {
        $value = (string)$value;
        if ($value === '') {
            return '';
        }
        $names = explode(',', $value);
        foreach ($names as $name) {
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_.]*$/D', $name)) {
                return null;
            }
        }
        return implode(',', array_values(array_unique($names)));
    }

    /**
     * The label of a class's rules; null when its ID is not a UUID - one with a line break after it
     * too, which an attribute in config.xml written by other means can hold: its rules' lines would be
     * split inside the label's quotes.
     */
    public static function label($uuid)
    {
        $uuid = strtolower((string)$uuid);
        if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/D', $uuid)) {
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
     *   id           its ID is not a UUID (config.xml written by other means)
     *   description  its description ends in a backslash (description())
     *   dscp         the DSCP to set is not one of 0 to 63
     *   match        the DSCP to match is not one of 1 to 63: pf cannot match 0, which it takes for no
     *                DSCP asked (pf.c:5805, "r->tos &&")
     *   protocol     a protocol this does not know
     *   port         a port field holding what is not taken here (port())
     *   ports        a port without TCP or UDP
     *   interface    an interface field that names none
     *   address      an address field that names none
     *   users        a groups and users field holding what is not a row ID of User Identity's
     *   application  an application or category field holding what is no name nDPI gives: a line break
     *   sources      groups or users beside a source other than any: both say where connections come from
     *   destinations applications or categories beside a destination other than any
     *   everything   nothing narrows it: it would mark every connection (narrows())
     *   family       no source, destination and IP version fit together
     *
     * Whether the tables a class names are there now is not a problem of the class: Sources says that,
     * at each filter reload, and rules() writes nothing while one side has none.
     */
    public static function problem(array $class, $uuid)
    {
        if (self::label($uuid) === null) {
            return 'id';
        }
        if (self::description($class['description'] ?? '') === null) {
            return 'description';
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
        $from = self::port($class['source_port'] ?? '');
        $to = self::port($class['destination_port'] ?? '');
        if ($from === null || $to === null) {
            return 'port';
        }
        if ($from . $to !== '' && !in_array($protocol, self::PORT_PROTOCOLS, true)) {
            return 'ports';
        }
        if (self::interfaces($class['interface'] ?? '') === null) {
            return 'interface';
        }
        if (self::addresses($class['source_net'] ?? '') === null || self::addresses($class['destination_net'] ?? '') === null) {
            return 'address';
        }
        if (Sources::users($class['users'] ?? '') === null) {
            return 'users';
        }
        if (Sources::names($class['application'] ?? '') === null || Sources::names($class['categories'] ?? '') === null) {
            return 'application';
        }
        list($users, $apps) = self::tabled($class);
        if ($users && self::addresses($class['source_net'] ?? '') !== ['any']) {
            return 'sources';
        }
        if ($apps && self::addresses($class['destination_net'] ?? '') !== ['any']) {
            return 'destinations';
        }
        if (!self::narrows($class)) {
            return 'everything';
        }
        if (empty(self::combinations($class['source_net'] ?? '', $class['destination_net'] ?? '', $class['ipprotocol'] ?? ''))) {
            return 'family';
        }
        return null;
    }

    /**
     * The rules of one class, as OPNsense's registerFilterRule() takes them; none when problem() says
     * why. $key is markKey()'s: the FilterRule key that writes the mark on this OPNsense. $tables is
     * Sources::resolve()'s for the class - its 'from' the tables of its groups and users, its 'to' those of
     * its applications and categories, each null when the class names none: a class that names them and
     * has no table on one side now makes no rule, and one given no $tables at all has none.
     */
    public static function rules(array $class, $uuid, $key, $tables = null)
    {
        if (self::problem($class, $uuid) !== null || !in_array($key, ['scrub', 'dn'], true)) {
            return [];
        }
        $ends = ['from' => $class['source_net'] ?? '', 'to' => $class['destination_net'] ?? ''];
        list($users, $apps) = self::tabled($class);
        foreach (['from' => $users, 'to' => $apps] as $side => $named) {
            if (!$named) {
                continue;
            }
            $found = is_array($tables) && is_array($tables[$side] ?? null) ? $tables[$side] : [];
            $names = array_values(array_unique(array_filter($found, function ($name) {
                return is_string($name) && preg_match(Sources::TABLE, $name);
            })));
            if (empty($names)) {
                return [];
            }
            $ends[$side] = implode(',', $names);
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
            'descr' => self::DESCR . self::description($class['description'] ?? ''),
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
        foreach (self::combinations($ends['from'], $ends['to'], $class['ipprotocol'] ?? '') as $pair) {
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
     * The line a filter reload writes into the rules file for a class it left idle - no rule only because
     * its groups and users, or its applications and categories, have no table now (problem() null,
     * Sources::idle()) - as registerFilterRule() takes it: a match rule registered disabled, which OPNsense
     * writes commented out (FilterRule.php:42, Rule.php:161-164), as it writes a scheduled rule out of its
     * time, disabled and described "[FIN]" (filter.inc:245-262). pf never reads it. apply.py reads it
     * (hardware.py's idle_in()), so that the switch keeps the class's place as this reload kept it
     * (Hardware::places()), the record and the rules coming from one reload in one file. A record written
     * anywhere else by the hook could come from a run that is no reload: Firewall: Rules lists the
     * automatic rules by calling every plugin's hook (list_non_mvc_rules.php), and leaves a disabled rule
     * out of the list. $why is what the system log says of it. null when the class's ID is not a UUID.
     */
    public static function idleRecord(array $class, $uuid, $why)
    {
        if (self::label($uuid) === null) {
            return null;
        }
        $text = self::description($class['description'] ?? '') ?? '';
        return [
            'type' => 'match',
            'direction' => 'in',
            'quick' => false,
            'disabled' => true,
            'disablereplyto' => true,
            'ipprotocol' => 'inet',
            'label' => self::IDLE_LABEL . strtolower((string)$uuid),
            'descr' => self::DESCR . $text . ' - makes no rule: ' . preg_replace('/[\r\n]+/', ' ', (string)$why),
        ];
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
