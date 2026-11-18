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
     * value the page would never take in a field nobody touched.
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        foreach ($this->classes->class->iterateItems() as $class) {
            if (!$validateFullModel && !$class->isFieldChanged()) {
                continue;
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
            if (!Marking::narrows($values)) {
                $messages->appendMessage(new Message(
                    gettext('Choose at least one of Interfaces, Source, Destination, a port or Arriving with DSCP: a class without any of them would mark every connection.'),
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
