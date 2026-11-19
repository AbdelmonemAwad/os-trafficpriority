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
     * nothing was applied yet. The page's cards ask it with the switch read again (status.py check:
     * entries 3 and 255 and port 0's mode, when the last Apply set them); the grids without.
     */
    public function statusAction()
    {
        return $this->status(true);
    }

    protected function status($check)
    {
        $result = json_decode((string)(new Backend())->configdRun('trafficpriority status' . ($check ? ' check' : '')), true);
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
     * no key for the mark); and its place in the switch's queues (status.py's hardware: why_not for the
     * whole switch, else the class's own); the page words it
     */
    public function searchAppliedAction()
    {
        $status = $this->status(false);
        $key = $this->markKey();
        $seen = [];
        foreach (($status['classes'] ?? []) as $row) {
            if (is_array($row) && isset($row['uuid'])) {
                $seen[(string)$row['uuid']] = $row;
            }
        }
        $hardware = is_array($status['hardware'] ?? null) ? $status['hardware'] : [];
        $places = is_array($hardware['classes'] ?? null) ? $hardware['classes'] : [];
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
                'switch_not' => (string)($hardware['why_not'] ?? 'unknown'),
                'switch' => is_array($places[strtolower((string)$uuid)] ?? null) ? $places[strtolower((string)$uuid)] : null,
            ];
        }
        return $this->searchRecordsetBase($rows, ['description', 'dscp'], 'sequence');
    }

    /**
     * the Firewall: Shaper tab's grid: each rule of Firewall: Shaper, with what the switch takes of it
     * and what stays with the host, and why (status.py's hardware.shaper, from shaper_map.py); the page
     * words each. Firewall: Shaper is read, never written.
     */
    public function searchShaperAction()
    {
        $status = $this->status(false);
        $rows = [];
        foreach (($status['hardware']['shaper'] ?? []) as $row) {
            if (!is_array($row) || !isset($row['uuid'])) {
                continue;
            }
            $rows[] = [
                'uuid' => (string)$row['uuid'],
                'sequence' => (int)($row['sequence'] ?? 0),
                'description' => (string)($row['description'] ?? ''),
                'interface' => (string)($row['interface'] ?? ''),
                'direction' => (string)($row['direction'] ?? ''),
                'target' => (string)($row['target'] ?? ''),
                'hardware' => is_array($row['hardware'] ?? null) ? $row['hardware'] : [],
                'host' => is_array($row['host'] ?? null) ? $row['host'] : [],
            ];
        }
        return $this->searchRecordsetBase($rows, ['description', 'interface', 'target'], 'sequence');
    }

    /**
     * the settings saved put into pf and the switch: the filter reloaded, whose hook
     * (plugins.inc.d/trafficpriority.inc) registers the classes' rules - the aliases are not reloaded,
     * nothing of theirs changed - and then the switch's queues set (scripts/trafficpriority/apply.py,
     * through os-xgs-npu's switch tool where there is one, and put back as found with Traffic Priority
     * off), in the background: the switch's reads and writes take seconds to a minute over the
     * coprocessor's link, and no request waits on them. What it did, and while it runs that it runs, is
     * in status.py's answer, which the page reads.
     */
    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $backend = new Backend();
        $out = trim((string)$backend->configdRun('filter reload skip_alias'));
        if (strpos($out, 'OK') !== 0) {
            return ['status' => 'failed', 'status_msg' => gettext('Filter reload did not finish.') . ' ' . $out];
        }
        $backend->configdRun('trafficpriority apply', true);
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
