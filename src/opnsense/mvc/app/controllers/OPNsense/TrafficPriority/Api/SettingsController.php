<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\TrafficPriority\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'trafficpriority';
    protected static $internalModelClass = '\OPNsense\TrafficPriority\TrafficPriority';

    public function searchClassAction()
    {
        return $this->searchBase('classes.class', null, 'sequence');
    }

    public function getClassAction($uuid = null)
    {
        return $this->getBase('class', 'classes.class', $uuid);
    }

    public function addClassAction()
    {
        return $this->addBase('class', 'classes.class');
    }

    public function setClassAction($uuid)
    {
        return $this->setBase('class', 'classes.class', $uuid);
    }

    public function delClassAction($uuid)
    {
        return $this->delBase('classes.class', $uuid);
    }

    public function toggleClassAction($uuid, $enabled = null)
    {
        return $this->toggleBase('classes.class', $uuid, $enabled);
    }
}
