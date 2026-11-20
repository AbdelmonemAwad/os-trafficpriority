<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\TrafficPriority;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

class TrafficPriority extends BaseModel
{
    /**
     * A class the rules hook would not write is refused at the save, with why, rather than taken and
     * left out of pf (Marking::problem(), the same test the hook and the page make). The whole class is
     * read when any field of it changed: OPNsense's own field types check only the fields that changed
     * (BaseModel::performValidation()), and config.xml written by other means than the page can hold a
     * value the page would never take in a field nobody touched. Whether the tables of its groups and
     * users, applications and categories are there now is not asked here: the other plugins make them at
     * their own Apply, before or after this one, and the page says for each what it has now.
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        /* every class, for what a minimum depends on: the others' order, DSCPs and minimums */
        $all = [];
        foreach ($this->classes->class->iterateItems() as $uuid => $class) {
            $all[(string)$uuid] = [];
            foreach (array_merge(Marking::FIELDS, ['minimum']) as $field) {
                $all[(string)$uuid][$field] = (string)$class->$field;
            }
        }
        $places = Hardware::places($all);
        foreach ($this->classes->class->iterateItems() as $uuid => $class) {
            if (!$validateFullModel && !$class->isFieldChanged()) {
                continue;
            }
            /*
             * A minimum is held by the switch's weighted queues (Hardware): only on a class with one of
             * its two places; the minimums of the classes switched on add up to 100 at most; and not
             * beside a class with a place and no minimum, which would be strict and go before it. A
             * class switched off holds none, and is not refused for one.
             */
            if (Hardware::minimum((string)$class->minimum) !== null && $places[(string)$uuid] !== 'off') {
                if ($places[(string)$uuid] !== 'hardware') {
                    self::refuse($messages, $class->minimum, gettext('A minimum is held by the switch queues, which take the first two DSCPs in the order of the list - classes that mark IPv4 above Best Effort and make a rule. The DSCP of this class is not one of them.'));
                } elseif (Hardware::total($all) > 100) {
                    self::refuse($messages, $class->minimum, gettext('The minimums of the classes switched on would add up to more than 100 percent.'));
                }
            }
            if ($places[(string)$uuid] === 'hardware' && Hardware::mixed($all)) {
                self::refuse($messages, $class->minimum, gettext('A minimum cannot be kept beside a strict class: give each class with a switch queue a minimum, or none.'));
            }
            $values = [];
            foreach (Marking::FIELDS as $field) {
                $values[$field] = (string)$class->$field;
            }
            if (Marking::description($values['description']) === null) {
                $text = gettext('A description cannot end with a backslash: pf would read the next line of the rules file as part of it.');
                self::refuse($messages, $class->description, $text);
            }
            $protocol = Marking::protocol($values['protocol']);
            foreach (['source_port', 'destination_port'] as $field) {
                $port = Marking::port($values[$field]);
                if ($port === null) {
                    self::refuse($messages, $class->$field, gettext('A port number, a name, an alias of ports or a range.'));
                } elseif ($port !== '' && !in_array($protocol, Marking::PORT_PROTOCOLS, true)) {
                    $messages->appendMessage(new Message(
                        gettext('A port can be given only with TCP, UDP or TCP/UDP.'),
                        $class->$field->__reference
                    ));
                }
            }
            foreach (['source_net', 'destination_net'] as $field) {
                $items = explode(',', $values[$field]);
                if (count($items) > 1 && in_array('any', $items, true)) {
                    $messages->appendMessage(new Message(
                        gettext('Any cannot be combined with other addresses.'),
                        $class->$field->__reference
                    ));
                }
            }
            /* an address field that names nothing is the field's own message (NetworkAliasField) */
            if (
                Marking::addresses($values['source_net']) !== null &&
                Marking::addresses($values['destination_net']) !== null &&
                empty(Marking::combinations($values['source_net'], $values['destination_net'], $values['ipprotocol']))
            ) {
                $messages->appendMessage(new Message(
                    gettext('No source and destination here fit the IP version chosen: an IPv4 and an IPv6 address cannot make one rule.'),
                    $class->ipprotocol->__reference
                ));
            }
            /*
             * Groups and users, applications and categories (Sources): a value that names none of them is
             * the field type's own message where the field changed, and this one where config.xml holds it
             * from other means; their tables take the place of Source and Destination, which pf could not
             * read with them in one rule.
             */
            if (Sources::users($values['users']) === null) {
                self::refuse($messages, $class->users, gettext('Choose groups and users of User Identity, or none.'));
            }
            foreach (['application' => gettext('Choose applications Application Control keeps a table for, or none.'),
                'categories' => gettext('Choose categories Application Control keeps a table for, or none.')] as $field => $text) {
                if (Sources::names($values[$field]) === null) {
                    self::refuse($messages, $class->$field, $text);
                }
            }
            list($users, $apps) = Marking::tabled($values);
            if ($users && Marking::addresses($values['source_net']) !== ['any']) {
                self::refuse($messages, $class->users, gettext('Groups and users take the place of Source: leave Source at any, or choose no group or user.'));
            }
            if ($apps && Marking::addresses($values['destination_net']) !== ['any']) {
                $field = Sources::items($values['application']) !== [] ? 'application' : 'categories';
                self::refuse($messages, $class->$field, gettext('Applications and categories take the place of Destination: leave Destination at any, or choose none of them.'));
            }
            if (!Marking::narrows($values)) {
                $messages->appendMessage(new Message(
                    gettext('Choose at least one of Interfaces, Source, Groups and users, Destination, Applications, Application categories, a port or Arriving with DSCP: a class without any of them would mark every connection.'),
                    $class->interface->__reference
                ));
            }
        }
        return $messages;
    }

    /**
     * A message for a field that has none yet: OPNsense's own field type, which checks a changed field
     * before this does, has said what is wrong with it in its own words.
     */
    private static function refuse($messages, $field, $text)
    {
        foreach ($messages as $message) {
            if ($message->getField() === $field->__reference) {
                return;
            }
        }
        $messages->appendMessage(new Message($text, $field->__reference));
    }
}
