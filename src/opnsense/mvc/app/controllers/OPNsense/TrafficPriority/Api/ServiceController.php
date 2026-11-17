<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\TrafficPriority\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\TrafficPriority\Marking;
use OPNsense\TrafficPriority\TrafficPriority;

class ServiceController extends ApiControllerBase
{
    /* the fields of a class, as config.xml and Marking::problem() have them */
    const FIELDS = ['enabled', 'sequence', 'description', 'interface', 'ipprotocol', 'protocol', 'source_net',
        'source_port', 'destination_net', 'destination_port', 'match_dscp', 'dscp'];

    public function statusAction()
    {
        $result = json_decode((new Backend())->configdRun('trafficpriority status'), true);
        return is_array($result) ? $result : ['error' => gettext('Status could not be read.')];
    }

    /**
     * the Applied tab's grid: each class of the settings, with what pf was given for it at the last
     * filter reload and what pf holds now (status.py, by the class's label), and - when the class makes
     * no rule - why, as the rules hook decides it (Marking::problem()); the page words it
     */
    public function searchAppliedAction()
    {
        $status = $this->statusAction();
        $seen = [];
        foreach (($status['classes'] ?? []) as $row) {
            if (is_array($row) && isset($row['uuid'])) {
                $seen[(string)$row['uuid']] = $row;
            }
        }
        $rows = [];
        foreach ((new TrafficPriority())->classes->class->iterateItems() as $uuid => $node) {
            $class = [];
            foreach (self::FIELDS as $field) {
                $class[$field] = (string)$node->$field;
            }
            $pf = $seen[(string)$uuid] ?? [];
            $rows[] = [
                'uuid' => (string)$uuid,
                'enabled' => $class['enabled'] === '1',
                'sequence' => (int)$class['sequence'],
                'description' => $class['description'],
                'dscp' => $node->dscp->getDescription(),
                'problem' => Marking::problem($class, (string)$uuid) ?? '',
                'written' => (int)($pf['written'] ?? 0),
                'not_placed' => (int)($pf['not_placed'] ?? 0),
                'rules' => (int)($pf['rules'] ?? 0),
                'states' => (int)($pf['states'] ?? 0),
                'created' => (int)($pf['created'] ?? 0),
                'packets' => (int)($pf['packets'] ?? 0),
                'bytes' => (int)($pf['bytes'] ?? 0),
            ];
        }
        return $this->searchRecordsetBase($rows, ['description', 'dscp'], 'sequence');
    }

    /**
     * the settings saved put into pf: the filter reloaded, whose hook (plugins.inc.d/trafficpriority.inc)
     * registers the classes' rules; the aliases are not reloaded, nothing of theirs changed
     */
    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $out = trim((string)(new Backend())->configdRun('filter reload skip_alias'));
        if (strpos($out, 'OK') !== 0) {
            return ['status' => 'failed', 'status_msg' => gettext('Filter reload did not finish.') . ' ' . $out];
        }
        return ['status' => 'ok'];
    }
}
