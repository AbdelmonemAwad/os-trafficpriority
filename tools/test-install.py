#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The installer, the removal, the package's two scripts and place-menu.sh, run in a temporary root.

The scripts are run with sh from a copy of the repository in which their absolute paths are moved
into the temporary root - /usr/local, PHP's /var/lib/php/tmp, the caches in /tmp, /sbin/pfctl - and
stand-ins answer for what only a firewall has: service, configctl and pfctl, each writing down how it
was called. Two things FreeBSD does otherwise are bridged in the copy, and only those: BSD's
`cp -R dir/` copies what dir holds, written `dir/.` for GNU's cp, and BSD's `mktemp -t prefix` takes
a prefix, which a stand-in gives GNU's mktemp. What is checked is what the scripts do: which files
are laid down and with which modes, where the menu goes, that nothing is copied when a file has a
syntax error, that the rules hook is gone before the filter reload that takes the classes' rules out
of pf, that nothing of the plugin is left, and what each says when pf still holds a rule of it. And the
switch's queues the plugin set, put back before its files go - by apply.py in uninstall.sh, by
os-xgs-npu's switch tool in post-deinstall.sh, and there only when the settings file is the plugin's.

    python3 tools/test-install.py"""
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = ['install/install.sh', 'install/uninstall.sh', 'pkg/post-install.sh', 'pkg/post-deinstall.sh',
           'src/opnsense/scripts/trafficpriority/place-menu.sh']
LOCAL = '/usr/local'
MENU = '/usr/local/opnsense/mvc/app/models/OPNsense/TrafficPriority/Menu/Menu.xml'
XGS = '/usr/local/opnsense/mvc/app/models/OPNsense/XGS/Menu/Menu.xml'
HOOK = '/usr/local/etc/inc/plugins.inc.d/trafficpriority.inc'
CACHES = ['/var/lib/php/tmp/opnsense_menu_cache.xml', '/var/lib/php/tmp/opnsense_acl_cache.json',
          '/tmp/opnsense_menu_cache.xml', '/tmp/opnsense_acl_cache.json']
COMMIT = '0123456789abcdef0123456789abcdef01234567'

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


class Box:
    """A temporary root, a copy of the repository whose scripts work in it, and the stand-ins."""

    def __init__(self, tmp):
        self.fake = os.path.join(tmp, 'root')
        self.repo = os.path.join(tmp, 'repo')
        self.bin = os.path.join(tmp, 'bin')
        self.calls = os.path.join(tmp, 'calls')
        self.pf = os.path.join(tmp, 'pf-rules')
        os.makedirs(self.fake)
        os.makedirs(self.bin)
        shutil.copytree(ROOT, self.repo, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc'))
        # every file as a checkout has it, not runnable: the scripts set what must be (a checkout on
        # some file systems makes every file runnable, and the modes would then prove nothing)
        for base, _, files in os.walk(self.repo):
            for name in files:
                os.chmod(os.path.join(base, name), 0o644)
        for script in SCRIPTS:
            path = os.path.join(self.repo, script)
            text = open(path, encoding='utf-8').read()
            # a path where one starts, not one inside another (/var/lib/php/tmp/ holds /tmp/ too)
            text = re.sub(r'(?<![\w/.-])(/usr/local/|/var/lib/php/tmp/|/tmp/opnsense_|/sbin/pfctl|/var/db/)',
                          lambda m: self.fake + m.group(1), text)
            text = text.replace('cp -R "${HERE}/src/" ', 'cp -R "${HERE}/src/." ')
            with open(path, 'w', encoding='utf-8', newline='\n') as handle:
                handle.write(text)
        hook = self.fake + HOOK
        # configctl and service write down each call; configctl also whether the rules hook was there
        self.stub('configctl', 'echo "configctl $* hook=$([ -f %s ] && echo yes || echo no)" >> %s\necho OK'
                  % (hook, self.calls))
        self.stub('service', 'echo "service $*" >> %s' % self.calls)
        self.stub('mktemp', 'if [ "$1" = -d ] && [ "$2" = -t ]; then exec /usr/bin/env mktemp -d '
                            '"${TMPDIR:-/tmp}/$3.XXXXXX"; fi\nexec /usr/bin/env mktemp "$@"', real='mktemp')
        # pfctl -s rules: what the test puts in pf-rules
        os.makedirs(self.fake + '/sbin')
        self.write(self.fake + '/sbin/pfctl', '#!/bin/sh\necho "pfctl $*" >> %s\ncat %s 2>/dev/null\n'
                   % (self.calls, self.pf), 0o755)
        # python3, as the firewall's: what it was asked to run, by the script's last two path parts
        self.python()

    def python(self):
        self.write(self.fake + '/usr/local/bin/python3', '#!/bin/sh\necho "python3 $(basename $(dirname $1))/$(basename $1) '
                   '$2" >> %s\n' % self.calls, 0o755)

    def stub(self, name, body, real=None):
        path = os.path.join(self.bin, name)
        if real:
            # the stand-in must not find itself: the real one is looked for past this directory
            body = body.replace('/usr/bin/env mktemp', shutil.which(real, path=os.defpath) or '/usr/bin/mktemp')
        self.write(path, '#!/bin/sh\n' + body + '\n', 0o755)

    @staticmethod
    def write(path, text, mode=0o644):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(text)
        os.chmod(path, mode)

    def run(self, script, *args):
        env = dict(os.environ, PATH=self.bin + os.pathsep + os.environ.get('PATH', ''), TMPDIR=os.path.dirname(self.fake))
        done = subprocess.run(['sh', os.path.join(self.repo, script)] + list(args), env=env,
                              capture_output=True, text=True, timeout=300)
        return done.returncode, done.stdout + done.stderr

    def called(self):
        try:
            return open(self.calls, encoding='utf-8').read().splitlines()
        except OSError:
            return []

    def forget(self):
        if os.path.exists(self.calls):
            os.remove(self.calls)

    def plugin_files(self):
        """Every file under the root's /usr/local that the plugin has a hand in."""
        out = []
        for base, _, files in os.walk(self.fake + LOCAL):
            for name in files:
                path = os.path.join(base, name)[len(self.fake):]
                if 'trafficpriority' in path.lower() or 'TrafficPriority' in path:
                    out.append(path)
        return sorted(out)

    def mode(self, path):
        return stat.S_IMODE(os.stat(self.fake + path).st_mode)

    def read(self, path):
        """A file of the root, or None when it is not there."""
        try:
            return open(self.fake + path, encoding='utf-8').read()
        except OSError:
            return None


def source_files():
    out = []
    for base, _, files in os.walk(os.path.join(ROOT, 'src')):
        for name in files:
            if name.endswith('.pyc') or '__pycache__' in base:
                continue
            out.append(LOCAL + os.path.join(base, name)[len(os.path.join(ROOT, 'src')):].replace(os.sep, '/'))
    return sorted(out)


with tempfile.TemporaryDirectory() as tmp:
    box = Box(tmp)
    menu_own = open(os.path.join(ROOT, 'src/opnsense/scripts/trafficpriority/menu/own.xml'), encoding='utf-8').read()
    menu_xgs = open(os.path.join(ROOT, 'src/opnsense/scripts/trafficpriority/menu/xgs.xml'), encoding='utf-8').read()
    place = 'src/opnsense/scripts/trafficpriority/place-menu.sh'

    # place-menu.sh: XGS where os-xgs-npu's menu is, Firewall where it is not; the menu caches cleared
    for cache in CACHES:
        box.write(box.fake + cache, 'cached')
    rc, out = box.run(place)
    check('place-menu.sh without os-xgs-npu: own, the Firewall menu file', (rc, out.strip(),
          box.read(MENU)), (0, 'own', menu_own))
    check('place-menu.sh: the menu caches cleared', [c for c in CACHES[::2] if os.path.exists(box.fake + c)], [])
    box.write(box.fake + XGS, '<menu/>')
    rc, out = box.run(place)
    check('place-menu.sh with os-xgs-npu: xgs, the XGS menu file', (rc, out.strip(),
          box.read(MENU)), (0, 'xgs', menu_xgs))
    check('place-menu.sh own, os-xgs-npu there: own', (box.run(place, 'own')[1].strip(),
          box.read(MENU) == menu_own), ('own', True))
    os.remove(box.fake + XGS)
    check('place-menu.sh xgs, os-xgs-npu not there: xgs', box.run(place, 'xgs')[1].strip(), 'xgs')
    check('place-menu.sh: the menu file readable by the GUI', box.mode(MENU), 0o644)
    shutil.rmtree(box.fake + LOCAL)

    # install.sh: nothing copied when a file of the tree has a syntax error
    broken = os.path.join(box.repo, 'src/opnsense/mvc/app/library/OPNsense/TrafficPriority/Marking.php')
    kept = open(broken, encoding='utf-8').read()
    with open(broken, 'w', encoding='utf-8') as handle:
        handle.write(kept.replace('class Marking', 'class Marking {', 1))
    rc, out = box.run('install/install.sh')
    check('install.sh, a PHP file with a syntax error: stopped, nothing copied, no reload',
          (rc != 0, box.plugin_files(), box.called()), (True, [], []))
    with open(broken, 'w', encoding='utf-8') as handle:
        handle.write(kept)

    # install.sh: every file of src/ laid down, the menu placed, the caches cleared, the filter reloaded
    for cache in CACHES:
        box.write(box.fake + cache, 'cached')
    box.write(os.path.join(box.repo, '.source-commit'), COMMIT + ' 2026-11-17T12:00:00+00:00\n')
    rc, out = box.run('install/install.sh')
    check('install.sh: done, and where the page is said', (rc, out.strip().splitlines()[-1:]),
          (0, ['Traffic Priority installed: Firewall > Traffic Priority']))
    laid = [f for f in box.plugin_files() if not f.startswith('/usr/local/share/') and f != MENU]
    check('install.sh: every file of src/ laid down, and nothing else', laid, source_files())
    check('install.sh: the menu file placed', box.read(MENU), menu_own)
    check('install.sh: the caches cleared', [c for c in CACHES if os.path.exists(box.fake + c)], [])
    check('install.sh: configd restarted, then the filter reloaded with the hook in place',
          box.called(), ['service configd restart', 'configctl filter reload skip_alias hook=yes'])
    check('install.sh: the modes', [box.mode(p) for p in (
        '/usr/local/opnsense/scripts/trafficpriority/status.py',
        '/usr/local/opnsense/scripts/trafficpriority/self-update.py',
        '/usr/local/opnsense/scripts/trafficpriority/place-menu.sh',
        HOOK,
        '/usr/local/opnsense/service/conf/actions.d/actions_trafficpriority.conf',
        '/usr/local/opnsense/scripts/trafficpriority/i18n/ui/source.json',
        '/usr/local/opnsense/scripts/trafficpriority/menu/own.xml',
        '/usr/local/opnsense/scripts/trafficpriority/release-keys/xgs-release-key-13ed7f86.pub')],
        [0o755, 0o755, 0o755, 0o644, 0o644, 0o644, 0o644, 0o644])
    installed = box.read('/usr/local/share/os-trafficpriority/installed.json') or ''
    check('install.sh: the commit recorded for the self-update, from the stamp',
          ('"commit": "%s"' % COMMIT in installed, '"source": "stamp"' in installed), (True, True))

    # install.sh again, os-xgs-npu there: the XGS menu, and a release key the tree no longer has gone
    box.write(box.fake + XGS, '<menu/>')
    old_key = '/usr/local/opnsense/scripts/trafficpriority/release-keys/dropped.pub'
    box.write(box.fake + old_key, 'a key no longer in the tree')
    box.forget()
    rc, out = box.run('install/install.sh')
    check('install.sh again, os-xgs-npu there: XGS > Traffic Priority, the XGS menu file',
          (rc, out.strip().splitlines()[-1:], box.read(MENU)),
          (0, ['Traffic Priority installed: XGS > Traffic Priority'], menu_xgs))
    check('install.sh again: a release key the tree no longer holds removed', os.path.exists(box.fake + old_key), False)

    # uninstall.sh: everything gone, the hook before the reload, and pf asked
    os.makedirs(box.fake + '/usr/local/opnsense/scripts/trafficpriority/__pycache__', exist_ok=True)
    box.write(box.fake + '/var/db/os-trafficpriority/hardware.json', '{}')
    box.python()
    box.forget()
    rc, out = box.run('install/uninstall.sh')
    check('uninstall.sh: nothing of the plugin left', box.plugin_files(), [])
    check('uninstall.sh: its directories gone', [d for d in (
        '/usr/local/opnsense/mvc/app/models/OPNsense/TrafficPriority',
        '/usr/local/opnsense/mvc/app/library/OPNsense/TrafficPriority',
        '/usr/local/opnsense/scripts/trafficpriority', '/usr/local/share/os-trafficpriority')
        if os.path.exists(box.fake + d)], [])
    check('uninstall.sh: os-xgs-npu\'s own menu left alone', os.path.exists(box.fake + XGS), True)
    check('uninstall.sh: the switch put back first, the hook removed before the filter reload, then pf asked',
          box.called(), ['python3 trafficpriority/apply.py clear', 'service configd restart',
                         'configctl filter reload skip_alias hook=no', 'pfctl -s rules'])
    check('uninstall.sh: what the page kept of the switch gone', os.path.exists(box.fake + '/var/db/os-trafficpriority'), False)
    check('uninstall.sh: pf holds none of its rules - said, and done', (rc, 'none of its rules is left' in out), (0, True))

    # uninstall.sh when pf still holds rules of it: said, and exit 1
    box.run('install/install.sh')
    with open(box.pf, 'w', encoding='utf-8') as handle:
        handle.write('match in on igb1 inet all set ( tos 0xb8 ) label "trafficpriority-6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a01"\n'
                     'match in on igb2 inet all set ( tos 0xb8 ) label "trafficpriority-6f3b0e2c-1a4d-4c8e-9b7a-2d5e8f1c3a01"\n'
                     'pass in quick on igb1 inet all keep state label "02f4bab031b57d1e30553ce08e0ec131"\n')
    rc, out = box.run('install/uninstall.sh')
    check('uninstall.sh, pf still holding two of its rules: said, and exit 1', (rc, 'still holds 2 of its rules' in out), (1, True))

    # the package: pkg lays down the files of src/, with the modes tools/make-package.sh gives them,
    # and post-install places the menu and reloads the filter; then pkg removes those files, and
    # post-deinstall clears what it leaves - the menu file, Python's caches, the plugin's directories
    # once empty - and asks pf
    os.remove(box.pf)
    os.remove(box.fake + XGS)
    shutil.rmtree(box.fake + LOCAL)
    shutil.copytree(os.path.join(box.repo, 'src'), box.fake + LOCAL)
    box.python()
    for path in source_files():
        os.chmod(box.fake + path, 0o755 if path.endswith(('.py', '.sh')) else 0o644)
    box.write(box.fake + '/usr/local/sbin/configctl', '#!/bin/sh\nexec configctl "$@"\n', 0o755)
    box.write(box.fake + '/usr/local/etc/rc.d/configd', '#!/bin/sh\nservice configd "$@"\n', 0o755)
    box.forget()
    rc, out = box.run('pkg/post-install.sh')
    check('post-install.sh: the menu placed, said', (rc, box.read(MENU) == menu_own,
          'the page is at Firewall > Traffic Priority' in out), (0, True, True))
    check('post-install.sh: configd restarted and the filter reloaded',
          box.called(), ['service configd restart', 'configctl filter reload skip_alias hook=yes'])
    os.chmod(box.fake + '/usr/local/opnsense/scripts/trafficpriority/place-menu.sh', 0o644)
    rc, out = box.run('pkg/post-install.sh')
    check('post-install.sh, place-menu.sh not runnable: said', 'its menu file was not written' in out, True)

    # pkg removes the package's files - every file of src/ - then runs post-deinstall
    os.makedirs(box.fake + '/usr/local/opnsense/scripts/trafficpriority/__pycache__', exist_ok=True)
    box.write(box.fake + '/usr/local/opnsense/scripts/trafficpriority/__pycache__/status.cpython-311.pyc', 'x')
    for path in source_files():
        os.remove(box.fake + path)
    # os-xgs-npu's switch tool, and the settings file it keeps as this plugin wrote it
    box.write(box.fake + '/usr/local/opnsense/scripts/xgs/switch_qos.py', '# the switch tool\n', 0o755)
    settings = box.fake + '/var/db/os-xgs-npu/switch-qos.json'
    box.write(settings, '{\n "classes": [],\n "owner": "os-trafficpriority"\n}\n')
    box.write(box.fake + '/var/db/os-trafficpriority/hardware.json', '{}')
    box.forget()
    rc, out = box.run('pkg/post-deinstall.sh')
    check('post-deinstall.sh: the switch put back through os-xgs-npu\'s tool, the settings file being the plugin\'s',
          (box.called()[:1], os.path.exists(box.fake + '/var/db/os-trafficpriority')), (['python3 xgs/switch_qos.py clear'], False))
    box.write(settings, '{\n "owner": "os-something"\n}\n')
    box.forget()
    box.run('pkg/post-deinstall.sh')
    check('post-deinstall.sh: another plugin\'s settings file left alone', [c for c in box.called() if c.startswith('python3')], [])
    os.remove(settings)
    os.remove(box.fake + '/usr/local/opnsense/scripts/xgs/switch_qos.py')
    box.forget()
    rc, out = box.run('pkg/post-deinstall.sh')
    check('post-deinstall.sh: nothing of the plugin left - the menu file and Python\'s caches with it',
          box.plugin_files(), [])
    check('post-deinstall.sh: the menu\'s directory and the plugin\'s own, once empty, gone', [d for d in (
        '/usr/local/opnsense/mvc/app/models/OPNsense/TrafficPriority/Menu',
        '/usr/local/opnsense/mvc/app/library/OPNsense/TrafficPriority',
        '/usr/local/opnsense/scripts/trafficpriority') if os.path.exists(box.fake + d)], [])
    check('post-deinstall.sh: configd restarted, the filter reloaded without the hook, pf asked',
          box.called(), ['service configd restart', 'configctl filter reload skip_alias hook=no', 'pfctl -s rules'])
    check('post-deinstall.sh: none of its rules left - said', (rc, 'none of its rules is left' in out), (0, True))

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
