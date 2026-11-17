<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The rules plugins.inc.d/trafficpriority.inc registers for sample configurations, written out by
 * OPNsense's own classes - the Plugin, FilterRule, Rule and Util of the OPNsense tree OPNSENSE_CORE
 * names (its opnsense/mvc/app/library/OPNsense/Firewall/ is read: /usr/local on a firewall, or the
 * src/ of an opnsense/core checkout) - with stand-ins only for what they reach outside themselves:
 * the configuration (Config), the aliases (Alias) and the well-known ports (PortField). Each rule is
 * the line OPNsense would write into /tmp/rules.debug, checked against what pfctl takes on FreeBSD 15.1
 * (Marking.php cites the grammar). checks.yml runs it on OPNsense 26.7 and 26.7.9: the first has no
 * key of its own for pf's scrub options, the second has.
 *
 *   OPNSENSE_CORE=<core checkout>/src php tools/test-rules.php
 */

namespace OPNsense\Core {
    /* Plugin's constructor reads system settings (Plugin.php:52-71), each with empty(); none is set */
    class Config
    {
        private static $instance = null;

        public static function getInstance()
        {
            if (self::$instance === null) {
                self::$instance = new Config();
            }
            return self::$instance;
        }

        public function object()
        {
            return (object)['system' => (object)[]];
        }
    }
}

namespace OPNsense\Base\FieldTypes {
    /* Rule::mapAddressInfo() asks it for a port it cannot otherwise place (Rule.php:122-130) */
    class PortField
    {
        public static function getWellKnown($search = null)
        {
            $known = ['https' => '443', 'sip' => '5060'];
            if ($search === null) {
                return $known;
            }
            return isset($known[$search]) ? [$search => $known[$search]] : [];
        }
    }
}

namespace OPNsense\Firewall {
    /* the aliases: Rule's address map (Rule.php:61-66) and Util::isAlias() (Util.php:217-249) */
    class AliasList
    {
        public function iterateItems()
        {
            foreach (Alias::$given as $i => $alias) {
                yield 'uuid-' . $i => (object)$alias;
            }
        }
    }

    class Alias
    {
        public static $given = [
            ['name' => 'phones', 'type' => 'host', 'content' => '192.168.1.20'],
            ['name' => 'voip_ports', 'type' => 'port', 'content' => '5060'],
        ];
        public $aliases;

        public function __construct($lazy = false)
        {
            $this->aliases = (object)['alias' => new AliasList()];
        }

        public function flushCache()
        {
        }

        public function getByName($name)
        {
            foreach (self::$given as $alias) {
                if ($alias['name'] === $name) {
                    return (object)$alias;
                }
            }
            return null;
        }
    }
}

namespace {
    $root = dirname(__DIR__);
    $core = rtrim((string)getenv('OPNSENSE_CORE'), '/');
    $lib = $core . '/opnsense/mvc/app/library/OPNsense/Firewall';
    if ($core === '' || !is_file($lib . '/FilterRule.php')) {
        echo "FAIL OPNSENSE_CORE must name an OPNsense tree holding opnsense/mvc/app/library/OPNsense/Firewall/\n";
        exit(1);
    }
    foreach (['Util', 'Rule', 'FilterRule', 'Plugin'] as $class) {
        require $lib . '/' . $class . '.php';
    }
    require $root . '/src/opnsense/mvc/app/library/OPNsense/TrafficPriority/Marking.php';
    require $root . '/src/etc/inc/plugins.inc.d/trafficpriority.inc';

    use OPNsense\TrafficPriority\Marking;

    $failed = 0;
    $checks = 0;
    $logged = [];
    Marking::$log = function ($priority, $message) {
        global $logged;
        $logged[] = $message;
    };

    function check($ok, $what)
    {
        global $failed, $checks;
        $checks++;
        if (!$ok) {
            $failed++;
            echo "FAIL $what\n";
        }
    }

    const U1 = '6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a01';
    const U2 = '6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a02';
    const U3 = '6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a03';

    /* the filter's interface mapping, as filter_core_get_initialized_plugin_system() builds it
       (filter.lib.inc:54-84) */
    function net()
    {
        return [
            'wan' => ['if' => 'igb0', 'descr' => 'WAN', 'ipaddr' => 'dhcp', 'ipaddrv6' => 'dhcp6',
                'gateway' => '198.51.100.1', 'gatewayv6' => 'fe80::1'],
            'lan' => ['if' => 'igb1', 'descr' => 'LAN', 'ipaddr' => '192.168.1.1', 'subnet' => '24',
                'ipaddrv6' => 'track6', 'gateway' => null, 'gatewayv6' => null],
            'opt1' => ['if' => 'igb2', 'descr' => 'VOIP', 'ipaddr' => '10.0.0.1', 'subnet' => '24',
                'gateway' => null, 'gatewayv6' => null],
        ];
    }

    /* a class as config.xml's legacy array carries it, the model's defaults beneath */
    function cls($uuid, $fields = [])
    {
        return array_merge(['@attributes' => ['uuid' => $uuid], 'enabled' => '1', 'sequence' => '100',
            'description' => 'Voice', 'interface' => '', 'ipprotocol' => 'inet', 'protocol' => 'any',
            'source_net' => 'any', 'source_port' => '', 'destination_net' => 'any', 'destination_port' => '',
            'match_dscp' => '', 'dscp' => '46'], $fields);
    }

    /* $enabled null: no Enabled saved at all, as before the General tab was ever saved */
    function cfg($classes, $enabled = '1')
    {
        return ['OPNsense' => ['TrafficPriority' => ['general' => $enabled === null ? [] : ['enabled' => $enabled],
            'classes' => ['class' => $classes]]]];
    }

    /* Rule keeps its address map in a static the first rule fills (Rule.php:48-67); emptied for each
       configuration, as each filter reload is a process of its own */
    function fresh_rule_statics()
    {
        $map = new ReflectionProperty(\OPNsense\Firewall\Rule::class, 'aliasMap');
        if (PHP_VERSION_ID < 80100) {
            $map->setAccessible(true);
        }
        $map->setValue(null, []);
    }

    /* the lines OPNsense writes for what the hook registered, with $before registered first */
    function render($config, $before = null, $fw = null)
    {
        global $logged;
        $GLOBALS['config'] = $config;
        $logged = [];
        fresh_rule_statics();
        $fw = $fw ?? new \OPNsense\Firewall\Plugin();
        $mapping = net();
        $fw->setInterfaceMapping($mapping);
        if ($before !== null) {
            $fw->registerFilterRule(1, $before);
        }
        trafficpriority_firewall($fw);
        $lines = [];
        foreach (explode("\n", $fw->outputFilterRules()) as $line) {
            if ($line !== '' && strpos($line, '# [prio:') !== 0) {
                $lines[] = $line;
            }
        }
        return $lines;
    }

    function ours($lines)
    {
        return array_values(array_filter($lines, function ($line) {
            return strpos($line, 'label "trafficpriority-') !== false;
        }));
    }

    /*
     * One line as pfctl takes it for a match rule of this plugin (parse.y:2350 pfrule, 3109 match,
     * 2797 tos, 2932 scrub, 1516 set-tos): the direction in, never quick, no state, no route-to or
     * reply-to, the DSCP's two low bits (ECN) clear, the label within the 63 characters FilterRule
     * keeps (FilterRule.php:71).
     */
    function pf_shape($line)
    {
        $list = '(\{[^{}]+\}|\$[A-Za-z_][A-Za-z0-9_]*)';
        $shape = '/^match in( on [A-Za-z0-9_.]+)? (inet|inet6)( proto (tcp|udp|\{tcp udp\}))? from ' . $list .
            '( port ' . $list . ')? to ' . $list . '( port ' . $list . ')?' .
            '((?: tos 0x[0-9a-f]{2})?) scrub \( set-tos 0x[0-9a-f][048c] \)((?: tos 0x[0-9a-f]{2})?)' .
            ' label "trafficpriority-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" # Traffic Priority: [^\n]*$/';
        if (!preg_match($shape, $line, $m)) {
            return false;
        }
        $label = [];
        preg_match('/label "([^"]*)"/', $line, $label);
        return substr_count($line, 'set-tos') === 1 && !($m[11] !== '' && $m[12] !== '') &&
            strlen($label[1]) <= 63 && strpos($line, ' quick') === false && strpos($line, 'state') === false &&
            strpos($line, 'route-to') === false && strpos($line, 'reply-to') === false;
    }

    $hasScrub = method_exists(\OPNsense\Firewall\FilterRule::class, 'parseScrub');
    echo 'OPNsense at ' . $core . ': FilterRule ' . ($hasScrub ? 'with' : 'without') . " a scrub key\n";

    /* off */
    check(count(render([])) === 0, 'no settings at all: no rule');
    check(count(ours(render(cfg([cls(U1)], '0')))) === 0, 'Traffic Priority off: no rule');
    check(count(ours(render(cfg([cls(U1)], null)))) === 0, 'Enabled never saved, a class there: no rule (off by default)');
    check(count(ours(render(cfg([])))) === 0, 'on, no class: no rule');

    /* one class: UDP to the SIP port, coming in on the LAN, EF */
    $one = ours(render(cfg([cls(U1, ['interface' => 'lan', 'protocol' => 'udp', 'destination_port' => '5060'])])));
    check(count($one) === 1, 'one class on one interface: one rule (' . count($one) . ')');
    $want = 'match in on igb1 inet proto udp from {any} to {any} port {5060} scrub ( set-tos 0xb8 ) label "trafficpriority-'
        . U1 . '" # Traffic Priority: Voice';
    check(($one[0] ?? '') === $want, "the rule as OPNsense writes it:\n      want $want\n      got  " . ($one[0] ?? '-'));
    check(pf_shape($one[0] ?? ''), 'its shape is one pfctl takes');
    check(strpos($one[0] ?? '', ' quick') === false, 'not quick: the owner\'s rules still decide');
    /* OPNsense 26.7 to 26.7.2 note "Gateway not allowed" above every rule that is not a pass, its own
       block rules too (FilterRule.php:195-198 in 26.7); from 26.7.3 only above one given a gateway or a
       reply-to (FilterRule.php:214-219), which FilterRule adds on an interface with a gateway unless
       told not to (FilterRule.php:157) */
    $wan = render(cfg([cls(U1, ['interface' => 'wan'])]), ['type' => 'block', 'descr' => 'a control block rule',
        'ipprotocol' => 'inet', 'interface' => 'lan']);
    $control = array_search(true, array_map(function ($l) {
        return strpos($l, 'a control block rule') !== false;
    }, $wan), true);
    $always = $control !== false && strpos($wan[$control - 1] ?? '', 'Gateway not allowed') !== false;
    check(count(ours($wan)) === 1 && strpos(ours($wan)[0], 'reply-to') === false &&
        ($always || strpos(implode("\n", $wan), 'Gateway not allowed') === false),
        'no reply-to on a WAN class' . ($always ? ' (this OPNsense notes "Gateway not allowed" above every non-pass rule)' :
        ', and no debug line from FilterRule about one'));
    check(strpos($one[0] ?? '', 'dnpipe') === false && strpos($one[0] ?? '', 'dnqueue') === false &&
        !class_exists('OPNsense\TrafficShaper\TrafficShaper', false), 'nothing of Firewall: Shaper read or written');

    /* before OPNsense's own rules: priority 0 */
    $all = render(cfg([cls(U1)]), ['type' => 'pass', 'descr' => 'an early quick pass', 'ipprotocol' => 'inet']);
    $at = array_search(ours($all)[0] ?? '', $all, true);
    $early = array_search(true, array_map(function ($l) {
        return strpos($l, 'an early quick pass') !== false;
    }, $all), true);
    check($at !== false && $early !== false && $at < $early, 'written before a rule OPNsense registers at priority 1');

    /* interfaces */
    $two = ours(render(cfg([cls(U1, ['interface' => 'lan,opt1'])])));
    check(count($two) === 2 && strpos($two[0], 'match in on igb1 ') === 0 && strpos($two[1], 'match in on igb2 ') === 0,
        'two interfaces: a rule on each');
    $any = ours(render(cfg([cls(U1)])));
    check(count($any) === 1 && strpos($any[0], ' on ') === false, 'no interface chosen: one rule, on every interface');
    foreach (['lan,,opt1', '0', 'lan,0', ' ', 'lan opt1'] as $bad) {
        $none = ours(render(cfg([cls(U1, ['interface' => $bad])])));
        check(count($none) === 0 && strpos(implode(' ', $GLOBALS['logged']), '(interface)') !== false,
            'interface field ' . json_encode($bad) . ': no rule, never one on every interface, and the log says why');
    }
    $gone = render(cfg([cls(U1, ['interface' => 'opt9'])]));
    check(count(ours($gone)) === 1 && strpos(ours($gone)[0], '#') === 0,
        'an interface no longer there: the rule written commented out by OPNsense, not on every interface');

    /* IP versions and addresses */
    $both = ours(render(cfg([cls(U1, ['ipprotocol' => 'inet46'])])));
    check(count($both) === 2 && strpos($both[0], 'match in inet ') === 0 && strpos($both[1], 'match in inet6 ') === 0,
        'IPv4 and IPv6, no address: a rule for each');
    $v4 = ours(render(cfg([cls(U1, ['ipprotocol' => 'inet46', 'source_net' => '192.168.1.20'])])));
    check(count($v4) === 1 && strpos($v4[0], 'match in inet from {192.168.1.20} ') === 0,
        'IPv4 and IPv6 with an IPv4 source: the IPv4 rule only');
    $mixed = ours(render(cfg([cls(U1, ['ipprotocol' => 'inet46', 'source_net' => '192.168.1.20',
        'destination_net' => '2001:db8::5'])])));
    check(count($mixed) === 0 && strpos(implode(' ', $GLOBALS['logged']), '(family)') !== false,
        'an IPv4 source to an IPv6 destination: no rule (pfctl would refuse the whole rule set), and the log says why');
    check(count(ours(render(cfg([cls(U1, ['source_net' => '2001:db8::/64'])])))) === 0,
        'an IPv4 class with an IPv6 source: no rule');
    $pairs = ours(render(cfg([cls(U1, ['ipprotocol' => 'inet46', 'source_net' => '192.168.1.20,2001:db8::20'])])));
    check(count($pairs) === 2 && strpos($pairs[0], 'inet from {192.168.1.20}') !== false &&
        strpos($pairs[1], 'inet6 from {2001:db8::20}') !== false, 'one source of each version: a rule each, in its own version');
    $alias = ours(render(cfg([cls(U1, ['source_net' => 'phones'])])));
    check(count($alias) === 1 && strpos($alias[0], ' from $phones to ') !== false, 'an alias as source: its table, by name');
    $lan = ours(render(cfg([cls(U1, ['destination_net' => 'lan'])])));
    check(count($lan) === 1 && strpos($lan[0], ' to {(igb1:network)} ') !== false, 'an interface\'s network as destination');
    $self = ours(render(cfg([cls(U1, ['destination_net' => '(self)', 'protocol' => 'tcp', 'destination_port' => '443'])])));
    check(count($self) === 1 && strpos($self[0], ' to {(self)} port {443} ') !== false, 'the firewall itself as destination');
    foreach (['0', 'lan net', 'a"b'] as $bad) {
        check(count(ours(render(cfg([cls(U1, ['source_net' => $bad])])))) === 0 &&
            strpos(implode(' ', $GLOBALS['logged']), '(address)') !== false,
            'source ' . json_encode($bad) . ': no rule, never one from any address');
    }
    $anyto = ours(render(cfg([cls(U1, ['destination_net' => 'any,192.168.1.30'])])));
    check(count($anyto) === 1 && strpos($anyto[0], ' to {any} ') !== false, 'any among other destinations: any');

    /* protocols and ports */
    $tu = ours(render(cfg([cls(U1, ['protocol' => 'tcp/udp', 'destination_port' => '10000-20000'])])));
    check(count($tu) === 1 && strpos($tu[0], ' proto {tcp udp} ') !== false && strpos($tu[0], ' port {10000:20000} ') !== false,
        'TCP/UDP and a range: both protocols, the range as pf writes it');
    $sp = ours(render(cfg([cls(U1, ['protocol' => 'udp', 'source_port' => '3074'])])));
    check(count($sp) === 1 && strpos($sp[0], ' from {any} port {3074} to {any} ') !== false, 'a source port');
    $pa = ours(render(cfg([cls(U1, ['protocol' => 'udp', 'destination_port' => 'voip_ports'])])));
    check(count($pa) === 1 && strpos($pa[0], ' port $voip_ports ') !== false, 'an alias of ports');
    foreach (['any', ''] as $protocol) {
        check(count(ours(render(cfg([cls(U1, ['protocol' => $protocol, 'destination_port' => '5060'])])))) === 0 &&
            strpos(implode(' ', $GLOBALS['logged']), '(ports)') !== false,
            'a port with protocol ' . json_encode($protocol) . ': no rule (pfctl refuses a port without TCP or UDP)');
    }
    check(count(ours(render(cfg([cls(U1, ['protocol' => 'icmp'])])))) === 0, 'a protocol the model does not offer: no rule');
    $anyport = ours(render(cfg([cls(U1, ['destination_port' => 'any'])])));
    check(count($anyport) === 1 && strpos($anyport[0], ' port ') === false, 'port any, as the port field offers it: no port, any protocol');

    /* DSCPs */
    $match = ours(render(cfg([cls(U1, ['match_dscp' => '10'])])));
    check(count($match) === 1 && substr_count($match[0], ' tos 0x28') === 1 && pf_shape($match[0]),
        'arriving with AF11: tos 0x28 matched, the mark set');
    check(count(ours(render(cfg([cls(U1, ['match_dscp' => '0'])])))) === 0 &&
        strpos(implode(' ', $GLOBALS['logged']), '(match)') !== false, 'matching DSCP 0: no rule (pf cannot match 0)');
    $zero = ours(render(cfg([cls(U1, ['dscp' => '0'])])));
    check(count($zero) === 1 && strpos($zero[0], 'scrub ( set-tos 0x00 )') !== false, 'Best Effort (0) set: set-tos 0x00');
    foreach (['8' => '0x20', '34' => '0x88', '56' => '0xe0', '63' => '0xfc'] as $dscp => $tos) {
        $r = ours(render(cfg([cls(U1, ['dscp' => (string)$dscp])])));
        check(count($r) === 1 && strpos($r[0], 'scrub ( set-tos ' . $tos . ' )') !== false, "DSCP $dscp: set-tos $tos");
    }
    foreach (['64', '-1', 'ef', ''] as $bad) {
        check(count(ours(render(cfg([cls(U1, ['dscp' => $bad])])))) === 0 &&
            strpos(implode(' ', $GLOBALS['logged']), '(dscp)') !== false, 'DSCP ' . json_encode($bad) . ': no rule');
    }

    /* the classes together */
    $order = ours(render(cfg([cls(U1, ['description' => 'Voice', 'sequence' => '10', 'dscp' => '46']),
        cls(U2, ['description' => 'Bulk', 'sequence' => '200', 'dscp' => '8']),
        cls(U3, ['description' => 'Video', 'sequence' => '50', 'dscp' => '34'])])));
    $names = array_map(function ($l) {
        return substr($l, strrpos($l, ': ') + 2);
    }, $order);
    check($names === ['Bulk', 'Video', 'Voice'], 'the highest sequence first, so the lowest is applied last and its DSCP kept: '
        . implode(', ', $names));
    $tie = ours(render(cfg([cls(U1, ['description' => 'First']), cls(U2, ['description' => 'Second'])])));
    check(strpos($tie[1] ?? '', 'First') !== false, 'the same sequence: the one first in the list applied last');
    $off = ours(render(cfg([cls(U1, ['enabled' => '0']), cls(U2, ['description' => 'On'])])));
    check(count($off) === 1 && strpos($off[0], U2) !== false, 'a class switched off: no rule of its');
    check(count(ours(render(cfg([cls('', ['description' => 'no id'])])))) === 0 &&
        strpos(implode(' ', $GLOBALS['logged']), '(id)') !== false, 'a class without a UUID: no rule');
    check(count(ours(render(cfg(cls(U1))))) === 1, 'one class, as config.xml\'s array holds a single one: its rule');
    $nl = ours(render(cfg([cls(U1, ['description' => "two\nlines"])])));
    check(count($nl) === 1 && count(explode("\n", $nl[0])) === 1, 'a description with a new line: still one line');

    /* a rule refused: the reload goes on, the other classes with it */
    $refusing = new class extends \OPNsense\Firewall\Plugin {
        public function registerFilterRule($prio, $conf, $defaults = null, ...$more)
        {
            if (strpos($conf['descr'] ?? '', 'Refused') !== false) {
                throw new \RuntimeException('refused');
            }
            parent::registerFilterRule($prio, $conf, $defaults, ...$more);
        }
    };
    $kept = [];
    try {
        $kept = ours(render(cfg([cls(U1, ['description' => 'Refused', 'sequence' => '1']),
            cls(U2, ['description' => 'Kept', 'sequence' => '2'])]), null, $refusing));
        $threw = false;
    } catch (\Throwable $e) {
        $threw = true;
    }
    check(!$threw, 'a rule OPNsense refuses: the hook does not throw, so the reload goes on');
    check(count($kept) === 1 && strpos($kept[0], 'Kept') !== false && strpos(implode(' ', $GLOBALS['logged']), 'refused') !== false,
        'the other class still registered, and the refusal logged');

    /* every line written above passes pfctl's shape */
    $every = ours(render(cfg([cls(U1, ['interface' => 'lan,opt1', 'ipprotocol' => 'inet46', 'protocol' => 'tcp',
        'destination_port' => '443', 'match_dscp' => '46', 'source_net' => 'phones,192.168.1.0/24'])])));
    check(count($every) === 6, 'two interfaces, two sources, both versions: 6 rules (' . count($every) . ')');
    foreach ($every as $line) {
        check(pf_shape($line), "pfctl's shape: $line");
    }

    /* the key that writes the mark */
    check(Marking::markKey() === ($hasScrub ? 'scrub' : 'dn'), "this OPNsense's key: " . Marking::markKey());
    check(Marking::markKey(['scrub' => 'parseScrub', 'dn' => 'parsePlain']) === 'scrub', 'a FilterRule with scrub: scrub');
    check(Marking::markKey(['dn' => 'parsePlain']) === 'dn', 'one with dn written as given only: dn');
    check(Marking::markKey(['dn' => 'parsePlain,dnpipe ']) === null && Marking::markKey([]) === null,
        'neither: none, so no rule rather than one pfctl refuses');
    check(Marking::rules(cls(U1), U1, null) === [] && Marking::rules(cls(U1), U1, 'tos') === [], 'no key: no rule');

    echo ($failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n");
    exit($failed ? 1 : 0);
}
