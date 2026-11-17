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
    /**
     * status.py's answer, and whether this OPNsense writes the mark at all: with no FilterRule key for
     * it the rules hook applies no class (Marking::markKey()), and the page says so rather than that
     * nothing was applied yet.
     */
    public function statusAction()
    {
        $result = json_decode((string)(new Backend())->configdRun('trafficpriority status'), true);
        if (!is_array($result)) {
            return ['error' => gettext('Status could not be read.')];
        }
        $result['writes_mark'] = $this->markKey() !== null;
        return $result;
    }

    /**
     * the Applied tab's grid: each class of the settings, with what pf was given for it at the last
     * filter reload and what pf holds now (status.py, by the class's label), and - when the class makes
     * no rule - why, as the rules hook decides it (Marking::problem(), and 'key' when this OPNsense has
     * no key for the mark); the page words it
     */
    public function searchAppliedAction()
    {
        $status = $this->statusAction();
        $key = $this->markKey();
        $seen = [];
        foreach (($status['classes'] ?? []) as $row) {
            if (is_array($row) && isset($row['uuid'])) {
                $seen[(string)$row['uuid']] = $row;
            }
        }
        $rows = [];
        foreach ((new TrafficPriority())->classes->class->iterateItems() as $uuid => $node) {
            $class = [];
            foreach (Marking::FIELDS as $field) {
                $class[$field] = (string)$node->$field;
            }
            $pf = $seen[strtolower((string)$uuid)] ?? [];
            $rows[] = [
                'uuid' => (string)$uuid,
                'enabled' => $class['enabled'] === '1',
                'sequence' => (int)$class['sequence'],
                'description' => $class['description'],
                'dscp' => $node->dscp->getDescription(),
                'problem' => Marking::problem($class, (string)$uuid) ?? ($key === null ? 'key' : ''),
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

    /**
     * The FilterRule key the hook writes the mark with on this OPNsense; null when there is none.
     */
    protected function markKey()
    {
        try {
            return Marking::markKey();
        } catch (\Throwable $e) {
            return null;
        }
    }
}
