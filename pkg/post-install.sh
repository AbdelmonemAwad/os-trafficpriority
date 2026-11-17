#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) after the files of os-trafficpriority are in place, on install and on upgrade alike.
# tools/make-package.sh inlines it into the package manifest. The first block and the registration
# are what every OPNsense plugin runs; the chmod lines and syntax checks of install/install.sh are
# not repeated, for the reasons os-netreport's post-install gives.

if [ -f /usr/local/etc/rc.d/configd ]; then
	/usr/local/etc/rc.d/configd restart
fi

if [ -f /usr/local/opnsense/mvc/script/run_migrations.php ]; then
	/usr/local/opnsense/mvc/script/run_migrations.php OPNsense/TrafficPriority
fi

if [ -x /usr/local/opnsense/scripts/firmware/register.php ]; then
	/usr/local/opnsense/scripts/firmware/register.php install os-trafficpriority > /dev/null 2>&1 || true
fi

if [ -f /usr/local/etc/rc.configure_plugins ]; then
	echo "Reloading plugin configuration"
	/usr/local/etc/rc.configure_plugins POST_INSTALL
fi

# the rules hook is read at a filter reload; an upgrade's new hook takes effect now. Nothing is marked
# until Traffic Priority is switched on and a class applied (off by default).
[ -f /usr/local/sbin/configctl ] && /usr/local/sbin/configctl filter reload skip_alias > /dev/null 2>&1 || true

# The page's place in the menu: the XGS section where os-xgs-npu is installed, Firewall where it is
# not. The menu file is not one of the package's files; place-menu.sh writes it and says which it
# chose.
WHERE=
if [ -x /usr/local/opnsense/scripts/trafficpriority/place-menu.sh ]; then
	WHERE=$(/usr/local/opnsense/scripts/trafficpriority/place-menu.sh) || WHERE=
fi
case "${WHERE}" in
xgs)	echo "Traffic Priority installed: the page is at XGS > Traffic Priority" ;;
own)	echo "Traffic Priority installed: the page is at Firewall > Traffic Priority" ;;
*)	echo "Traffic Priority installed; its menu file was not written: run /usr/local/opnsense/scripts/trafficpriority/place-menu.sh" ;;
esac
