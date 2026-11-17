#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Remove the Traffic Priority plugin files. The classes' rules go with the filter reload run here,
# because they are registered by the hook removed below, and the script says whether pf still holds
# any of them. Kept: the settings in config.xml. A connection opened while a class marked it keeps
# its mark until it ends: pf fixed it in the connection's state, and nothing here cuts a connection.

# the rules hook first, so the reload below is one without it
rm -f /usr/local/etc/inc/plugins.inc.d/trafficpriority.inc
rm -rf /usr/local/share/os-trafficpriority
rm -f /usr/local/opnsense/service/conf/actions.d/actions_trafficpriority.conf
rm -rf /usr/local/opnsense/scripts/trafficpriority
# the menu file place-menu.sh wrote, which is not one of src/'s files
rm -f /usr/local/opnsense/mvc/app/models/OPNsense/TrafficPriority/Menu/Menu.xml
rmdir /usr/local/opnsense/mvc/app/models/OPNsense/TrafficPriority/Menu 2>/dev/null || true
rm -rf /usr/local/opnsense/mvc/app/models/OPNsense/TrafficPriority
rm -rf /usr/local/opnsense/mvc/app/controllers/OPNsense/TrafficPriority
rm -rf /usr/local/opnsense/mvc/app/views/OPNsense/TrafficPriority
rm -rf /usr/local/opnsense/mvc/app/library/OPNsense/TrafficPriority
service configd restart > /dev/null
# PHP keeps them in its own temporary directory on 26.7 (/var/lib/php/tmp); /tmp is where they were
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json \
    /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
configctl filter reload skip_alias > /dev/null 2>&1 || true

# None of the classes' rules is left in pf when that reload loaded. When it did not, OPNsense loads
# the rule set before it again (filter.inc), the classes' rules with it: said, and the exit is 1.
LEFT=$(/sbin/pfctl -s rules 2> /dev/null | grep -c 'label "trafficpriority-')
if [ "${LEFT:-0}" -gt 0 ]; then
    echo "Traffic Priority removed, but pf still holds ${LEFT} of its rules: the filter reload did not load (see /tmp/rules.error); they go at the next reload that does"
    exit 1
fi
echo "Traffic Priority removed; none of its rules is left in pf, and its settings stay in config.xml"
