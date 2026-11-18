<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\TrafficPriority;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->generalForm = $this->getForm('general');
        $this->view->classForm = $this->getForm('dialogClass');
        $this->view->formGridClass = $this->getFormGrid('dialogClass');
        $this->view->pick('OPNsense/TrafficPriority/index');
    }
}
