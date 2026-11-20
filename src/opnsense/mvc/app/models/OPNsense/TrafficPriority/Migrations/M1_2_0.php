<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\TrafficPriority\Migrations;

use OPNsense\Base\BaseModelMigration;

/**
 * Version 1.2.0 (2026-11-20): a class takes groups and users of os-useridentity (users), and applications
 * and categories of os-appcontrol (application, categories). Three fields of each class are new, none of
 * them required and each empty by default: a class saved before names none of them, and marks what it
 * marked - the rules hook and every script read a missing one as none. Nothing saved before is changed.
 * This runs BaseModelMigration's own step, which gives a required field its default where none is set and
 * changes no value that is - the step 1.1.0 took without a file of its own - and records the version, so
 * that the next version's step knows where this one left the settings. run_migrations.php saves the
 * configuration after it; install/install.sh and pkg/post-install.sh run it.
 */
class M1_2_0 extends BaseModelMigration
{
    public function run($model)
    {
        parent::run($model);
    }
}
