#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) after the files of os-trafficpriority have been removed; not during an upgrade. The
# switch's queues it set are put back, and the rules hook is gone with the files, so a filter reload
# takes the classes' rules out of pf. Kept: the
# settings in config.xml. A connection opened while a class marked it keeps its mark until it ends:
# pf fixed it in the connection's state, and nothing here cuts a connection.

if [ -x /usr/local/opnsense/scripts/firmware/register.php ]; then
	/usr/local/opnsense/scripts/firmware/register.php remove os-trafficpriority > /dev/null 2>&1 || true
fi

# The switch's queues this plugin asked os-xgs-npu for, put back as found through os-xgs-npu's switch
# tool - apply.py is gone with the package's files - when the settings file it keeps is this plugin's;
# another plugin's is left alone.
Q=/var/db/os-xgs-npu/switch-qos.json
if [ -f "${Q}" ] && grep -q '"owner": "os-trafficpriority"' "${Q}" && [ -f /usr/local/opnsense/scripts/xgs/switch_qos.py ]; then
	/usr/local/bin/python3 /usr/local/opnsense/scripts/xgs/switch_qos.py clear > /dev/null 2>&1 || \
		echo "the switch's queues of Traffic Priority were not put back: /usr/local/opnsense/scripts/xgs/switch_qos.py show, then clear"
fi
rm -rf /var/db/os-trafficpriority

if [ -f /usr/local/etc/rc.d/configd ]; then
	/usr/local/etc/rc.d/configd restart
fi

if [ -f /usr/local/etc/rc.configure_plugins ]; then
	echo "Reloading plugin configuration"
	/usr/local/etc/rc.configure_plugins POST_DEINSTALL
fi

# The menu file place-menu.sh wrote is not one of the package's files, so pkg left it, and the
# model's directory with it. The menu is cached by PHP in /var/lib/php/tmp on 26.7, in /tmp before.
rm -f /usr/local/opnsense/mvc/app/models/OPNsense/TrafficPriority/Menu/Menu.xml
rmdir /usr/local/opnsense/mvc/app/models/OPNsense/TrafficPriority/Menu /usr/local/opnsense/mvc/app/models/OPNsense/TrafficPriority 2>/dev/null || true
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /tmp/opnsense_menu_cache.xml

# Nor what Python compiles beside a script it imports, which would keep the scripts' directory; the
# plugin's directories go once empty.
rm -rf /usr/local/opnsense/scripts/trafficpriority/__pycache__
for d in /usr/local/opnsense/scripts/trafficpriority /usr/local/opnsense/mvc/app/library/OPNsense/TrafficPriority; do
	[ -d "${d}" ] && find "${d}" -depth -type d -empty -delete 2> /dev/null
done

[ -f /usr/local/sbin/configctl ] && /usr/local/sbin/configctl filter reload skip_alias > /dev/null 2>&1 || true

# None of the classes' rules is left in pf when that reload loaded. When it did not, OPNsense loads
# the rule set before it again (filter.inc), the classes' rules with it: said here, not hidden.
LEFT=$(/sbin/pfctl -s rules 2> /dev/null | grep -c 'label "trafficpriority-')
if [ "${LEFT:-0}" -gt 0 ]; then
	echo "Traffic Priority removed, but pf still holds ${LEFT} of its rules: the filter reload did not load (see /tmp/rules.error); they go at the next reload that does"
else
	echo "Traffic Priority removed; none of its rules is left in pf, and its settings stay in config.xml"
fi
