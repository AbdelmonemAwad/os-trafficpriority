#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""Every string the GUI shows of this plugin, against every string the catalogue holds.

A msgid that reaches gettext without being in source.json is shown in English on an otherwise Arabic
page, and nothing in the build would have said so. Six places ask, and all six are read here, as
os-fanctl and os-frontpanel read theirs, because OPNsense passes each through gettext:

  page    the views' lang._()
  form    controllers/.../forms/*.xml: <label>, <help> and <hint>, which ControllerBase's
          parseFormNode() translates
  model   models/.../*.xml: <ValidationMessage> (BaseField::getValidationMessage()), <BlankDesc>
          (BaseListField::setBlankDesc()) and the text of each <OptionValues> entry - the DSCPs
          among them (OptionField)
  menu    the VisibleName of the menu files place-menu.sh writes as Menu.xml (MenuItem)
  ACL     its <name>, which the privilege pages translate (ACL::getPrivList()), and its
          <description>, as the family's other plugins have theirs in opnsense-arabic
  PHP     gettext() in the model, the controllers and the rules hook - the model's refusals at the
          save among them

A model's <description> is not among them: OPNsense shows it untranslated.

The mail is checked here too, and for the same reason. alerts.py reads the same
catalogue through gettext, which means its sentences can be wrong in two new ways: a
msgid it asks for that nobody translated, and a sentence it shares with the port grid
that the page has since reworded. The second is the one worth a build failure - an
alert and the page disagreeing about the same port is a bug, and it is invisible until
somebody with an Arabic GUI reads an alert about a port the page is describing
differently in the next window.

The Arabic is in opnsense-arabic's catalogue since 2026-10-22 (tools/arabic_catalogue.py), and a
catalogued string with no Arabic there fails - except on a contributor's pull request and on main,
where its Arabic may follow later and it is a warning (ARABIC_LATER, below).

    tools/check-strings.py            check, from the repository's root
    tools/check-strings.py --list     print every string the GUI shows, one JSON string a line
"""
import glob
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

BS = chr(92)
Q = chr(39)
DQ = chr(34)

# lang._('...') with backslash escapes inside, the way Volt writes them
PATTERN = re.compile("lang" + BS + "._" + BS + "(" + BS + "s*" + Q
                     + "((?:[^" + Q + BS + BS + "]|" + BS + BS + ".)*)" + Q
                     + BS + "s*" + BS + ")")
# Every call, however it is written, so that one this cannot read is reported rather than quietly
# left out: a quote is required after the bracket, because "lang._()" appears in prose too.
ANY_CALL = re.compile("lang" + BS + "._" + BS + "(" + BS + "s*[" + Q + DQ + "]")
# gettext('...') in PHP, single-quoted as the family writes it; and every gettext( at all
GETTEXT = re.compile("(?<![A-Za-z0-9_$>:])gettext" + BS + "(" + BS + "s*" + Q
                     + "((?:[^" + Q + BS + BS + "]|" + BS + BS + ".)*)" + Q + BS + "s*" + BS + ")")
GETTEXT_CALL = re.compile("(?<![A-Za-z0-9_$>:])gettext" + BS + "s*" + BS + "(")

VIEWS = 'src/opnsense/mvc/app/views/OPNsense/*/*.volt'
FORMS = 'src/opnsense/mvc/app/controllers/OPNsense/*/forms/*.xml'
MODELS = 'src/opnsense/mvc/app/models/OPNsense/*/*.xml'
ACLS = 'src/opnsense/mvc/app/models/OPNsense/*/ACL/ACL.xml'
MENUS = ('src/opnsense/scripts/*/menu/*.xml', 'src/opnsense/mvc/app/models/OPNsense/*/Menu/Menu.xml')
PHP = ('src/**/*.php', 'src/**/*.inc')


def unescape_php(raw):
    """A single-quoted PHP or Volt string's text: \\' and \\\\ are the only escapes."""
    return raw.replace(BS + Q, Q).replace(BS + BS, BS)


def collect():
    """({string: [where, ...]} for every string the GUI shows, [problems]) - a problem is a call
    this cannot read, or a text gettext would be asked for with spaces around it."""
    found = {}
    problems = []

    def add(text, where, kind):
        if text is None or not text.strip():
            return
        if text != text.strip():
            problems.append('%s (%s): spaces or line breaks around "%s"' % (where, kind, text.strip()[:60]))
        found.setdefault(text, []).append('%s %s' % (kind, where))

    for path in sorted(glob.glob(VIEWS)):
        text = open(path, encoding='utf-8').read()
        calls = PATTERN.findall(text)
        if len(ANY_CALL.findall(text)) != len(calls):
            problems.append('%s: %d lang._() calls not readable here'
                            % (path, len(ANY_CALL.findall(text)) - len(calls)))
        for raw in calls:
            add(unescape_php(raw), path, 'page')
    for path in sorted(glob.glob(FORMS)):
        for field in ET.parse(path).getroot().iter('field'):
            for tag in ('label', 'help', 'hint'):
                node = field.find(tag)
                if node is not None:
                    add(node.text, path, 'form')
    for path in sorted(glob.glob(MODELS)):
        root = ET.parse(path).getroot()
        for tag in ('ValidationMessage', 'BlankDesc'):
            for node in root.iter(tag):
                add(node.text, path, 'model')
        for options in root.iter('OptionValues'):
            for option in options:
                add(option.text, path, 'model')
    for path in sorted(glob.glob(ACLS)):
        for acl in ET.parse(path).getroot():
            for tag in ('name', 'description'):
                node = acl.find(tag)
                if node is not None:
                    add(node.text, path, 'ACL')
    for pattern in MENUS:
        for path in sorted(glob.glob(pattern)):
            for node in ET.parse(path).getroot().iter():
                add(node.get('VisibleName'), path, 'menu')
    for pattern in PHP:
        for path in sorted(glob.glob(pattern, recursive=True)):
            text = open(path, encoding='utf-8').read()
            calls = GETTEXT.findall(text)
            if len(GETTEXT_CALL.findall(text)) != len(calls):
                problems.append('%s: %d gettext() calls not readable here'
                                % (path, len(GETTEXT_CALL.findall(text)) - len(calls)))
            for raw in calls:
                add(unescape_php(raw), path, 'PHP')
    return found, problems


def main(argv):
    used, problems = collect()
    if '--list' in argv:
        for key in sorted(used):
            print(json.dumps(key, ensure_ascii=False))
        return 0

    base = 'src/opnsense/scripts/'
    name = sorted(glob.glob(base + '*/i18n/ui/source.json'))[0]
    src = set(json.load(open(name, encoding='utf-8')))
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import arabic_catalogue                                                  # noqa: E402

    # A contributor who does not write Arabic leaves it out (CONTRIBUTING.md). On a pull request from a
    # fork and on main, checks.yml sets ARABIC_LATER=1: a string without Arabic is then a warning on the
    # pull request and not a failure, and opnsense-arabic's "Strings waiting for Arabic" lists it until
    # its Arabic is there. A pull request from a branch of this repository still fails on one.
    later_ok = os.environ.get('ARABIC_LATER') == '1'

    try:
        ar = arabic_catalogue.catalogue()
    except (OSError, ValueError) as exc:
        print("opnsense-arabic's catalogue cannot be read: %s" % exc)
        return 1

    # The mail's msgids come from alerts.py itself rather than from a copy kept here, so
    # there is no second list to forget. It imports nothing outside the standard library,
    # which is why this can import it on a build runner with no OPNsense on it.
    mail, shared = set(), set()
    scripts = os.path.dirname(os.path.dirname(os.path.dirname(name)))   # .../<plugin>/i18n/ui -> .../<plugin>
    if os.path.exists(os.path.join(scripts, 'alerts.py')):
        sys.path.insert(0, scripts)
        import alerts                                                        # noqa: E402
        mail = set(alerts.mail_strings())
        shared = set(alerts.page_strings())

    page = {k for k, where in used.items() if any(w.startswith('page ') for w in where)}
    absent = sorted(set(used) - src)
    stale = sorted(src - set(used) - mail)
    missing = sorted(k for k in src if not ar.get(k))
    uncatalogued = sorted(mail - src)
    drifted = sorted(shared - page)

    kinds = {}
    for where in used.values():
        for kind in {w.split(' ', 1)[0] for w in where}:
            kinds[kind] = kinds.get(kind, 0) + 1
    print('shown by the GUI: %d (%s) | in the mail: %d | catalogued: %d | translated in opnsense-arabic: %d'
          % (len(used), ', '.join('%s %d' % (k, kinds[k]) for k in ('page', 'form', 'model', 'menu', 'ACL', 'PHP')
                                  if k in kinds), len(mail), len(src), len(src) - len(missing)))
    print('not readable here: %d' % len(problems))
    for problem in problems:
        print('   ! ' + problem)
    print('shown but not catalogued: %d' % len(absent))
    for key in absent:
        print('   + %s  (%s)' % (key[:100], used[key][0]))
    print('catalogued but unused: %d' % len(stale))
    for key in stale[:25]:
        print('   - ' + key[:100])
    print('catalogued but with no Arabic in opnsense-arabic: %d' % len(missing))
    for key in missing:
        print('   ? ' + key[:100])
    later(missing, later_ok)

    print('asked for by the mail but not catalogued: %d' % len(uncatalogued))
    for key in uncatalogued:
        print('   + ' + key[:100])
    print('the mail says this and the page no longer does: %d' % len(drifted))
    for key in drifted:
        print('   ! ' + key[:100])

    # Fatal: a string shown and not catalogued, which nothing would ever count as needing Arabic; a
    # call this cannot read, which is the same thing unseen; the two faults that make a message lie;
    # and a catalogued string with no Arabic - a step of the workflow enforced that one until
    # 2026-10-22 - unless ARABIC_LATER is set, where it is a warning. A string catalogued and no
    # longer shown is reported and not enforced: it costs a line in a JSON file.
    return 1 if absent or problems or uncatalogued or drifted or (missing and not later_ok) else 0


def later(keys, later_ok):
    """Each string without Arabic as a warning GitHub shows on the pull request, and in its summary."""
    if not later_ok:
        return
    for key in keys:
        print('::warning title=Arabic to follow::' +
              key.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A'))
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if keys and summary:
        with open(summary, 'a', encoding='utf-8') as handle:
            handle.write('### Strings waiting for Arabic\n\n' + ''.join('- %s\n' % key for key in keys))


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
