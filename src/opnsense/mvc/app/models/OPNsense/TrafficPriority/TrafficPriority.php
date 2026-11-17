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
     * left out of pf (Marking::problem(), the same test the hook and the page make).
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        foreach ($this->classes->class->iterateItems() as $class) {
            if (!$validateFullModel && !$class->isFieldChanged()) {
                continue;
            }
            $protocol = Marking::protocol((string)$class->protocol);
            foreach (['source_port', 'destination_port'] as $field) {
                if (Marking::port((string)$class->$field) !== '' && !in_array($protocol, Marking::PORT_PROTOCOLS, true)) {
                    $messages->appendMessage(new Message(
                        gettext('A port can be given only with TCP, UDP or TCP/UDP.'),
                        $class->$field->__reference
                    ));
                }
            }
            foreach (['source_net', 'destination_net'] as $field) {
                $items = explode(',', (string)$class->$field);
                if (count($items) > 1 && in_array('any', $items, true)) {
                    $messages->appendMessage(new Message(
                        gettext('Any cannot be combined with other addresses.'),
                        $class->$field->__reference
                    ));
                }
            }
            /* an address field that names nothing is the field's own message (NetworkAliasField) */
            if (
                Marking::addresses((string)$class->source_net) !== null &&
                Marking::addresses((string)$class->destination_net) !== null &&
                empty(Marking::combinations((string)$class->source_net, (string)$class->destination_net, (string)$class->ipprotocol))
            ) {
                $messages->appendMessage(new Message(
                    gettext('No source and destination here fit the IP version chosen: an IPv4 address and an IPv6 address cannot make one rule.'),
                    $class->ipprotocol->__reference
                ));
            }
        }
        return $messages;
    }
}
