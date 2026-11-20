<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The model's refusals at the save (TrafficPriority::performValidation()) and the page's API
 * (Api/ServiceController), run as OPNsense runs them, with stand-ins for what they reach of OPNsense's
 * MVC: BaseModel and its nodes and messages, ApiControllerBase, and configd (Backend). Marking is the
 * plugin's own; Util, Rule and FilterRule are OPNsense's, of the tree OPNSENSE_CORE names (as for
 * tools/test-rules.php); the aliases are stand-ins, the same two as there. And a minimum: refused at the
 * save on a class with no place in the switch's queues and when the minimums of the classes switched on
 * would add up to more than 100 (Hardware, the same cases as tools/test-hardware.py gives hardware.py);
 * the switch's queue of each class and each rule of Firewall: Shaper on the page; and Apply's second
 * half, the switch set after the filter reload.
 *
 * OPNsense's own field types are not run here. They check only the fields that changed
 * (BaseModel::performValidation()), and what they refuse is theirs - PortField a port with a line
 * break, typed into the page. What is tested is what the plugin adds: a class read whole when any
 * field of it changed, so a value config.xml holds from other means is refused too, and the field
 * type's own message, where it gave one, kept.
 *
 *   OPNSENSE_CORE=<core checkout>/src php tools/test-mvc.php
 */

namespace OPNsense\Firewall {
    /* Util::isAlias() and Util::isPortAlias() ask it (Util.php:217-266) */
    class Alias
    {
        public static $given = [
            ['name' => 'phones', 'type' => 'host', 'content' => '192.168.1.20'],
            ['name' => 'voip_ports', 'type' => 'port', 'content' => '5060'],
        ];

        public function __construct($lazy = false)
        {
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

namespace OPNsense\Base\Messages {
    /* OPNsense's Message, as the model and its callers use it */
    class Message
    {
        private $message;
        private $field;

        public function __construct($message, $field = '')
        {
            $this->message = $message;
            $this->field = $field;
        }

        public function getMessage()
        {
            return $this->message;
        }

        public function getField()
        {
            return $this->field;
        }
    }
}

namespace OPNsense\Base {
    /* what performValidation() returns: OPNsense's Validation, an ArrayObject of messages */
    class Validation extends \ArrayObject
    {
        public function appendMessage($message)
        {
            $this[] = $message;
        }
    }

    /*
     * BaseModel as TrafficPriority and ServiceController reach it: the classes, as nodes, from $given,
     * and - for the fields that changed - the messages of OPNsense's own field types, from $fieldMessages.
     */
    class BaseModel
    {
        /* uuid => ['values' => [field => value], 'changed' => true when a field of the class changed] */
        public static $given = [];
        /* [field reference, message] as a field type of OPNsense's would give them */
        public static $fieldMessages = [];
        public $classes;

        public function __construct()
        {
            $nodes = [];
            foreach (self::$given as $uuid => $class) {
                $nodes[$uuid] = new Node('classes.class.' . $uuid, $class['values'], !empty($class['changed']));
            }
            $this->classes = (object)['class' => new Items($nodes)];
        }

        public function performValidation($validateFullModel = false)
        {
            $messages = new Validation();
            foreach (self::$fieldMessages as $given) {
                $messages->appendMessage(new Messages\Message($given[1], $given[0]));
            }
            return $messages;
        }
    }

    class Items
    {
        private $nodes;

        public function __construct($nodes)
        {
            $this->nodes = $nodes;
        }

        public function iterateItems()
        {
            foreach ($this->nodes as $uuid => $node) {
                yield $uuid => $node;
            }
        }
    }

    /* a class: its fields by name, changed as ContainerField::isFieldChanged() says when one of them is */
    class Node
    {
        private $fields = [];
        private $changed;

        public function __construct($reference, $values, $changed)
        {
            foreach ($values as $name => $value) {
                $this->fields[$name] = new Field($reference . '.' . $name, $value);
            }
            $this->changed = $changed;
        }

        public function __get($name)
        {
            return $this->fields[$name] ?? new Field('', '');
        }

        public function isFieldChanged()
        {
            return $this->changed;
        }
    }

    /* a field: its value as a string, its reference, and - for an option - the text the model gives it */
    class Field
    {
        public static $options = [];
        public $__reference;
        private $value;

        public function __construct($reference, $value)
        {
            $this->__reference = $reference;
            $this->value = (string)$value;
        }

        public function __toString()
        {
            return $this->value;
        }

        public function getDescription()
        {
            return self::$options[$this->value] ?? $this->value;
        }
    }

    /* the API controller base: the request, and the grid's search, which here hands the rows back */
    class ApiControllerBase
    {
        public $request;

        public function __construct()
        {
            $this->request = new class {
                public $post = true;

                public function isPost()
                {
                    return $this->post;
                }
            };
        }

        protected function searchRecordsetBase($records, $fields = null, $defaultSort = null)
        {
            return ['rows' => $records, 'sort' => $defaultSort, 'fields' => $fields];
        }
    }
}

namespace OPNsense\Core {
    /* configd: what each command answers, and what was asked */
    class Backend
    {
        public static $answers = [];
        public static $asked = [];
        public static $detached = [];

        public function configdRun($event, $detach = false)
        {
            self::$asked[] = $event;
            if ($detach) {
                self::$detached[] = $event;
            }
            return self::$answers[$event] ?? null;
        }
    }
}

namespace {
    if (!function_exists('gettext')) {
        function gettext($text)
        {
            return $text;
        }
    }

    $root = dirname(__DIR__);
    $core = rtrim((string)getenv('OPNSENSE_CORE'), '/');
    $lib = $core . '/opnsense/mvc/app/library/OPNsense/Firewall';
    if ($core === '' || !is_file($lib . '/FilterRule.php')) {
        echo "FAIL OPNSENSE_CORE must name an OPNsense tree holding opnsense/mvc/app/library/OPNsense/Firewall/\n";
        exit(1);
    }
    foreach (['Util', 'Rule', 'FilterRule'] as $class) {
        require $lib . '/' . $class . '.php';
    }
    require $root . '/src/opnsense/mvc/app/library/OPNsense/TrafficPriority/Marking.php';
    require $root . '/src/opnsense/mvc/app/library/OPNsense/TrafficPriority/Hardware.php';
    require $root . '/src/opnsense/mvc/app/library/OPNsense/TrafficPriority/Sources.php';
    require $root . '/src/opnsense/mvc/app/models/OPNsense/TrafficPriority/TrafficPriority.php';
    require $root . '/src/opnsense/mvc/app/controllers/OPNsense/TrafficPriority/Api/ServiceController.php';

    use OPNsense\Base\BaseModel;
    use OPNsense\Base\Field;
    use OPNsense\Core\Backend;
    use OPNsense\TrafficPriority\Api\ServiceController;
    use OPNsense\TrafficPriority\Marking;
    use OPNsense\TrafficPriority\TrafficPriority;

    /* the text the model gives each DSCP it offers to set, from its XML (read without SimpleXML, which
       a PHP for the command line need not have) */
    $model = file_get_contents($root . '/src/opnsense/mvc/app/models/OPNsense/TrafficPriority/TrafficPriority.xml');
    preg_match('#<dscp type="OptionField">.*?</dscp>#s', $model, $block);
    preg_match_all('#<(\w+) value="([0-9]+)">([^<]+)</\1>#', $block[0] ?? '', $options, PREG_SET_ORDER);
    foreach ($options as $option) {
        Field::$options[$option[2]] = $option[3];
    }

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

    const U1 = '6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a01';
    const U2 = '6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a02';

    /* a class as the model holds it, its defaults beneath: UDP to 5060 coming in on the LAN */
    function cls($fields = [], $changed = true)
    {
        return ['changed' => $changed, 'values' => array_merge(['enabled' => '1', 'sequence' => '100',
            'description' => 'Voice', 'interface' => 'lan', 'ipprotocol' => 'inet', 'protocol' => 'udp',
            'source_net' => 'any', 'source_port' => '', 'destination_net' => 'any', 'destination_port' => '5060',
            'match_dscp' => '', 'dscp' => '46', 'minimum' => ''], $fields)];
    }

    /* the messages of a save: [field => [message, ...]], the field as its name in the class */
    function saved($classes, $fieldMessages = [], $full = false)
    {
        BaseModel::$given = $classes;
        BaseModel::$fieldMessages = $fieldMessages;
        $out = [];
        foreach ((new TrafficPriority())->performValidation($full) as $message) {
            $field = substr($message->getField(), strlen('classes.class.'));
            $out[$field][] = $message->getMessage();
        }
        return $out;
    }

    /* the field of class U1 named */
    function at($name, $uuid = U1)
    {
        return $uuid . '.' . $name;
    }

    /* the model: what the hook would not write is refused at the save, on the field it comes from */
    check(saved([U1 => cls()]) === [], 'a class UDP to 5060 on the LAN: saved');
    $everything = ['interface' => '', 'protocol' => 'any', 'destination_port' => ''];
    $all = saved([U1 => cls($everything)]);
    check(array_keys($all) === [at('interface')] && strpos($all[at('interface')][0], 'every connection') !== false,
        'a class that narrows nothing: refused, on Interfaces, saying it would mark every connection');
    foreach ([['protocol' => 'tcp'], ['ipprotocol' => 'inet46'], ['source_net' => 'any'], ['destination_port' => 'any'],
        ['description' => 'Everything']] as $fields) {
        check(isset(saved([U1 => cls($fields + $everything)])[at('interface')]),
            'narrowed by nothing but ' . json_encode($fields) . ': refused');
    }
    foreach ([['interface' => 'wan'], ['source_net' => '192.168.1.20'], ['destination_net' => '(self)'],
        ['protocol' => 'tcp', 'source_port' => '3074'], ['protocol' => 'tcp', 'destination_port' => 'voip_ports'],
        ['match_dscp' => '46']] as $fields) {
        check(saved([U1 => cls($fields + $everything)]) === [], 'narrowed by ' . json_encode($fields) . ' alone: saved');
    }

    $bs = chr(92);
    $back = saved([U1 => cls(['description' => 'Voice ' . $bs])]);
    check(array_keys($back) === [at('description')] && strpos($back[at('description')][0], 'backslash') !== false,
        'a description ending in a backslash: refused, on Description');
    check(isset(saved([U1 => cls(['description' => 'Voice' . $bs . "\n "])])[at('description')]),
        'a description ending in a backslash and a line break: refused');
    check(saved([U1 => cls(['description' => 'a' . $bs . 'b'])]) === [], 'a backslash inside a description: saved');
    check(saved([U1 => cls(['description' => 'Voice ' . $bs])], [['classes.class.' . at('description'), 'too long']]) ===
        [at('description') => ['too long']], 'the field type\'s own message on Description: kept, and no second one');

    foreach (["5060\npass in quick all\n#", 'phones', '20000-10000', '0', '{5060}'] as $port) {
        $got = saved([U1 => cls(['destination_port' => $port])]);
        check(array_keys($got) === [at('destination_port')] && count($got[at('destination_port')]) === 1,
            'destination port ' . json_encode($port) . ' in config.xml: refused, on Destination port, once');
    }
    check(array_keys(saved([U1 => cls(['source_port' => "1\n2"])])) === [at('source_port')],
        'a source port holding a line break: refused, on Source port');
    check(saved([U1 => cls(['destination_port' => 'phones'])], [['classes.class.' . at('destination_port'), 'not a port']]) ===
        [at('destination_port') => ['not a port']], 'PortField\'s own message on a port typed in: kept, and no second one');
    $bad = saved([U1 => cls(['description' => 'Renamed', 'destination_port' => "5060\n#"])]);
    check(isset($bad[at('destination_port')]), 'a class whose description changed: its port from config.xml read too, and refused');

    $noproto = saved([U1 => cls(['protocol' => 'any'])]);
    check(array_keys($noproto) === [at('destination_port')] && strpos($noproto[at('destination_port')][0], 'TCP') !== false,
        'a port with protocol any: refused, on the port');
    check(array_keys(saved([U1 => cls(['destination_net' => 'any,192.168.1.30'])])) === [at('destination_net')],
        'any among other destinations: refused, on Destination');
    check(array_keys(saved([U1 => cls(['source_net' => '192.168.1.20', 'destination_net' => '2001:db8::5'])])) ===
        [at('ipprotocol')], 'an IPv4 source to an IPv6 destination: refused, on IP version');

    /* a minimum: held by the switch's queues, so only on a class with one of its two places - the first
       two DSCPs in the list's order, IPv4, above Best Effort, of a class that makes a rule - the minimums
       adding up to 100 at most, and not beside a strict class: each class with a place has one, or none */
    $u3 = '6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a03';
    check(saved([U1 => cls(['minimum' => '30'])]) === [], 'a minimum on a class with a place: saved');
    check(saved([U1 => cls(['minimum' => '100'])]) === [], 'a minimum of 100: saved');
    $third = saved([U1 => cls(['minimum' => '10'], false), U2 => cls(['dscp' => '34', 'minimum' => '10'], false),
        $u3 => cls(['dscp' => '40', 'minimum' => '20'])]);
    check(array_keys($third) === [at('minimum', $u3)] && strpos($third[at('minimum', $u3)][0], 'first two DSCPs') !== false,
        'a minimum on a third DSCP: refused, on Minimum, saying the switch takes the first two');
    check(saved([U1 => cls(['minimum' => '10'], false), U2 => cls(['dscp' => '46', 'minimum' => '10'], false),
        $u3 => cls(['dscp' => '34', 'minimum' => '20'])]) === [],
        'a minimum on the second DSCP, the two classes of the first with theirs: saved');
    check(saved([U1 => cls(['sequence' => '300'], false), U2 => cls(['dscp' => '34', 'minimum' => '10'], false),
        $u3 => cls(['dscp' => '40', 'minimum' => '20', 'sequence' => '50'])]) === [],
        'a minimum on a class listed third but second by its sequence: saved');
    foreach (['0' => 'Best Effort', '8' => 'CS1, below it'] as $dscp => $what) {
        check(array_keys(saved([U1 => cls(['dscp' => (string)$dscp, 'minimum' => '20'])])) === [at('minimum')],
            'a minimum on ' . $what . ': refused');
    }
    check(array_keys(saved([U1 => cls(['ipprotocol' => 'inet6', 'minimum' => '20'])])) === [at('minimum')],
        'a minimum on a class marking IPv6 alone: refused');
    /* a minimum beside a strict class: refused on the class saved, whichever of the two it is */
    $beside = saved([U1 => cls([], false), U2 => cls(['dscp' => '34', 'minimum' => '30'])]);
    check(array_keys($beside) === [at('minimum', U2)] && strpos($beside[at('minimum', U2)][0], 'beside a strict class') !== false,
        'a minimum beside a strict class: refused, on Minimum');
    $strict = saved([U1 => cls(['description' => 'Renamed']), U2 => cls(['dscp' => '34', 'minimum' => '30'], false)]);
    check(array_keys($strict) === [at('minimum')] && strpos($strict[at('minimum')][0], 'beside a strict class') !== false,
        'a strict class saved beside one with a minimum: refused, on its Minimum');
    check(saved([U1 => cls(['interface' => '', 'destination_port' => '', 'protocol' => 'any'], false),
        U2 => cls(['dscp' => '34', 'minimum' => '30'])]) === [],
        'a class that makes no rule has no place: a minimum beside it is no mix');
    $over = saved([U1 => cls(['minimum' => '60'], false), U2 => cls(['dscp' => '34', 'minimum' => '50'])]);
    check(array_keys($over) === [at('minimum', U2)] && strpos($over[at('minimum', U2)][0], 'more than 100') !== false,
        'minimums of 60 and 50: the one saved refused, on Minimum');
    check(saved([U1 => cls(['minimum' => '60', 'enabled' => '0'], false), U2 => cls(['dscp' => '34', 'minimum' => '50'])]) === [],
        'a class switched off: its minimum not counted');
    check(saved([U1 => cls(['minimum' => '60', 'enabled' => '0'])]) === [], 'a class switched off: its own minimum not refused');
    check(saved([U1 => cls(['minimum' => '30'])], [['classes.class.' . at('minimum'), 'A percent from 1 to 100.']]) ===
        [at('minimum') => ['A percent from 1 to 100.']], 'the field type\'s own message on Minimum: kept, and no second one');

    /* only a class that changed is read, unless the whole model is */
    check(saved([U1 => cls($everything, false)]) === [], 'a class that did not change: not read');
    check(isset(saved([U1 => cls($everything, false)], [], true)[at('interface')]), 'the whole model validated: every class read');
    $two = saved([U1 => cls($everything, false), U2 => cls(['destination_port' => 'phones'])]);
    check(array_keys($two) === [at('destination_port', U2)], 'two classes: only the one that changed refused');

    /* the page's API: status.py's answer through configd, and what the Applied tab is given */
    $nokey = new class extends ServiceController {
        protected function markKey()
        {
            return null;
        }
    };
    $u3 = '6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a03';
    $u4 = '6F3B0E2C-1A4D-4C8E-9B7A-2D5E8F1C3A04';
    $hardware = ['why_not' => '', 'classes' => [
        U1 => ['why' => 'hardware', 'queue' => 7, 'kind' => 'strict', 'percent' => null, 'minimum' => null, 'minimum_why' => ''],
    ], 'shaper' => [
        ['uuid' => 'r1', 'sequence' => 1, 'description' => 'All up', 'interface' => 'wan', 'direction' => 'out',
            'target' => 'Up', 'hardware' => [['what' => 'limit', 'port' => 'Port2', 'kbit' => 100000]], 'host' => []],
        'not a row',
        ['uuid' => 'r2', 'sequence' => 2, 'description' => 'Voice', 'hardware' => 'not a list',
            'host' => [['why' => 'unmarked', 'dscp' => 34]]],
    ]];
    $answer = ['enabled' => true, 'pf' => true, 'refused' => false, 'marked' => 2, 'hardware' => $hardware, 'classes' => [
        ['uuid' => U1, 'written' => 2, 'not_placed' => 0, 'rules' => 2, 'states' => 4, 'created' => 19,
            'packets' => 48420, 'bytes' => 9924690],
        ['uuid' => strtolower($u4), 'written' => 1, 'not_placed' => 0, 'rules' => 0],
    ]];
    Backend::$answers = ['trafficpriority status check' => json_encode($answer)];
    Backend::$asked = [];
    $got = (new ServiceController())->statusAction();
    check(($got['marked'] ?? null) === 2 && ($got['writes_mark'] ?? null) === true && Marking::markKey() !== null &&
        Backend::$asked === ['trafficpriority status check'],
        'status: status.py\'s answer with the switch read again, and this OPNsense writes the mark');
    check(($nokey->statusAction()['writes_mark'] ?? null) === false, 'status: an OPNsense with no key for the mark: said');
    foreach (['', 'not json', '"a string"', null] as $bad) {
        Backend::$answers = ['trafficpriority status check' => $bad];
        check((new ServiceController())->statusAction() === ['error' => 'Status could not be read.'],
            'status: configd answering ' . json_encode($bad) . ': could not be read');
    }

    Backend::$answers = ['trafficpriority status' => json_encode($answer)];
    Backend::$asked = [];
    BaseModel::$given = [U1 => cls(), U2 => cls($everything), $u3 => cls(['destination_port' => "5060\n#"]),
        $u4 => cls(['description' => 'Upper', 'dscp' => '34']), '6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a05' => cls(['enabled' => '0'])];
    BaseModel::$fieldMessages = [];
    $grid = (new ServiceController())->searchAppliedAction();
    $rows = [];
    foreach ($grid['rows'] as $row) {
        $rows[strtolower($row['uuid'])] = $row;
    }
    $one = $rows[U1] ?? [];
    check(($one['problem'] ?? null) === '' && $one['enabled'] === true && $one['dscp'] === 'EF (46)' &&
        [$one['written'], $one['rules'], $one['states'], $one['created'], $one['packets']] === [2, 2, 4, 19, 48420],
        'applied: a class in pf, its counts from status.py and its DSCP as the model names it');
    check(($rows[U2]['problem'] ?? null) === 'everything' && ($rows[$u3]['problem'] ?? null) === 'port',
        'applied: why a class makes no rule, as the hook decides it');
    check(($rows[strtolower($u4)]['written'] ?? null) === 1 && $rows[strtolower($u4)]['dscp'] === 'AF41 (34)',
        'applied: a UUID in upper case in config.xml found in status.py\'s lower-case answer');
    check(($rows['6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a05']['enabled'] ?? null) === false, 'applied: a class switched off');
    check(Backend::$asked === ['trafficpriority status'], 'applied: the grid asks without reading the switch');
    check(($one['switch']['queue'] ?? null) === 7 && $one['switch_not'] === '' && $rows[U2]['switch'] === null,
        'applied: each class\'s switch queue from status.py, none for a class it does not name');
    $shaper = (new ServiceController())->searchShaperAction();
    check(count($shaper['rows']) === 2 && $shaper['rows'][0]['hardware'][0]['port'] === 'Port2' &&
        $shaper['rows'][1]['hardware'] === [] && $shaper['rows'][1]['host'][0]['why'] === 'unmarked' &&
        $shaper['rows'][1]['direction'] === '' && $shaper['sort'] === 'sequence',
        'Firewall: Shaper: each rule with what the switch takes and what stays with the host, a row that is none left out');
    Backend::$answers = ['trafficpriority status' => json_encode(['enabled' => false, 'classes' => []])];
    check((new ServiceController())->searchShaperAction()['rows'] === [] &&
        ((new ServiceController())->searchAppliedAction()['rows'][0]['switch_not'] ?? null) === 'unknown',
        'a status with no switch part: no rule, and the switch not known');
    Backend::$answers = ['trafficpriority status' => json_encode($answer)];
    check($grid['fields'] === ['description', 'dscp'] && $grid['sort'] === 'sequence', 'applied: searched by name and DSCP, by sequence');
    $keyless = [];
    foreach ($nokey->searchAppliedAction()['rows'] as $row) {
        $keyless[strtolower($row['uuid'])] = $row['problem'];
    }
    check(($keyless[U1] ?? null) === 'key' && ($keyless[U2] ?? null) === 'everything',
        'applied: with no key for the mark, every class that would make rules says so');

    Backend::$answers = ['filter reload skip_alias' => "OK\n"];
    Backend::$asked = [];
    Backend::$detached = [];
    $get = new ServiceController();
    $get->request->post = false;
    check($get->reconfigureAction() === ['status' => 'failed'] && Backend::$asked === [], 'apply: only by POST');
    check((new ServiceController())->reconfigureAction() === ['status' => 'ok'] &&
        Backend::$asked === ['filter reload skip_alias', 'trafficpriority apply'] &&
        Backend::$detached === ['trafficpriority apply'],
        'apply: the filter reloaded, the aliases left, OK taken, then the switch set in the background - its outcome in the status');
    Backend::$asked = [];
    foreach (['Execute error', '', null] as $out) {
        Backend::$answers = ['filter reload skip_alias' => $out];
        Backend::$asked = [];
        $failed_reload = (new ServiceController())->reconfigureAction();
        check(($failed_reload['status'] ?? '') === 'failed' &&
            strpos($failed_reload['status_msg'] ?? '', 'Filter reload did not finish.') === 0 &&
            !in_array('trafficpriority apply', Backend::$asked, true),
            'apply: configd answering ' . json_encode($out) . ': failed, and said; the switch not set');
    }

    echo ($failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n");
    exit($failed ? 1 : 0);
}
