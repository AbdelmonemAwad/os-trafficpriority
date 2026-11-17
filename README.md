<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/readme/banner-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/readme/banner-light.svg">
  <img src="docs/images/readme/banner-light.svg" alt="os-trafficpriority - Strict priority for chosen traffic, where it actually flows" width="100%">
</picture>

<p align="center">
  <img alt="status: written, not released" src="https://img.shields.io/badge/status-written%2C%20not%20released-lightgrey.svg?style=flat-square">
  <a href="https://github.com/AbdelmonemAwad/os-trafficpriority/actions/workflows/checks.yml"><img alt="checks on main" src="https://img.shields.io/github/actions/workflow/status/AbdelmonemAwad/os-trafficpriority/checks.yml?branch=main&amp;style=flat-square&amp;label=checks"></a>
  <a href="LICENSE"><img alt="licence: BSD-2-Clause" src="https://img.shields.io/badge/licence-BSD--2--Clause-blue.svg?style=flat-square"></a>
  <a href="#what-is-tested"><img alt="OPNsense 26.7" src="https://img.shields.io/badge/OPNsense-26.7-d94f00.svg?style=flat-square"></a>
  <a href="https://github.com/AbdelmonemAwad/opnsense-arabic"><img alt="the page in English and in Arabic" src="https://img.shields.io/badge/GUI-English%20%C2%B7%20Arabic-2da44e.svg?style=flat-square"></a>
  <a href="https://github.com/AbdelmonemAwad/os-xgs-npu"><img alt="part of os-xgs-npu" src="https://img.shields.io/badge/part%20of-os--xgs--npu-9a6700.svg?style=flat-square"></a>
</p>

# Traffic Priority for OPNsense

Strict priority for chosen traffic - voice, games, the firewall's own management - applied where that traffic actually flows: in the queues of a Sophos XGS's coprocessor and of its switch, which forwarded traffic never leaves.

> ~~**Planned - nothing here runs yet.** This repository was opened on 2026-10-22 to hold
> Traffic Priority as a plugin of its own. No code has been written or moved into it, and there is no
> release.~~
>
> **Written, not released (2026-11-17).** The first part is here: classes of connections, each
> marked with a DSCP by pf. Which switch queue a marked frame then waits in is the next part, and
> is not measured yet. Nothing has been installed on an appliance; what was run is under
> [What is tested](#what-is-tested).

<p align="center"><b>Contents:</b> <a href="#what-it-does">What it does</a> &middot; <a href="#how-a-class-marks-its-connections">How a class marks its connections</a> &middot; <a href="#on-a-sophos-xgs">On a Sophos XGS</a> &middot; <a href="#not-yet-and-why">Not yet, and why</a> &middot; <a href="#what-is-tested">What is tested</a> &middot; <a href="#installation">Installation</a> &middot; <a href="#updates">Updates</a> &middot; <a href="#where-it-fits">Where it fits</a> &middot; <a href="#licence">Licence</a></p>

## What it does

**Firewall: Traffic Priority** (XGS: Traffic Priority when os-xgs-npu is installed), one page:

- **classes** - each one a description, a sequence, and what it matches: the interfaces connections
  come in on (none chosen: every one), the IP version (IPv4 by default), the protocol, the source and
  destination (addresses, networks, aliases, an interface's network, the firewall itself), their
  ports (a number, a name, a range or an alias of ports), and the DSCP a connection arrives with
  (any by default); and the DSCP to set, EF (46) by default, one of the 21 code points Firewall:
  Shaper names;
- **the rules** - registered by the plugin at every filter reload (`plugins.inc.d/trafficpriority.inc`,
  the way os-blocklists registers its own), one pf `match` rule for each interface, IP version and
  pair of addresses a class names. They are never added to the owner's own rules, so turning the
  plugin off or removing it leaves nothing there. Firewall: Shaper and Firewall: Settings:
  Normalization are neither read nor written;
- **Applied** - for each class, what pf holds of it: its rules, the connections marked now and since
  they were loaded, the packets and bytes pf saw, and - when a class makes no rule - why. The
  switch's queue is "not measured yet" for every class;
- **General** - Enabled, **off by default**: nothing is marked until it is switched on and Applied.

Off, the rules are gone at the next filter reload; the classes stay.

## How a class marks its connections

A class is one rule like this, written by OPNsense's own rule class into `/tmp/rules.debug`:

```
match in on igb1 inet proto udp from {any} to {any} port {5060} scrub ( set-tos 0xb8 ) label "trafficpriority-<the class's ID>" # Traffic Priority: Voice
```

Read in FreeBSD 15.1's pf, which OPNsense 26.7 runs (opnsense/src stable/26.7 at `1633399de9dd`),
and in OPNsense 26.7's filter code:

- **a match rule decides nothing** - pf applies its actions and goes on to the next rule
  (`pf.c:5836-5867`), so the owner's rules still pass or block. It is never quick: pf stops at a
  quick rule that matches, a match rule too (`pf.c:5891`);
- **it comes first** - priority 0, before every rule OPNsense writes (its own begin at 1), so no
  quick rule ahead of it can leave it unread;
- **the mark goes with the connection, both ways** - the state the owner's pass rule makes takes the
  match rules' actions (`pf.c:5867`, `6274`), and every packet of the state, either way, gets them
  (`pf.c:11389`, `11401`): the DSCP written, the two ECN bits kept as they came (`pf_norm.c:2245-2262`);
- **a mark is fixed when a connection opens** - a class changed, added or removed reaches the
  connections opened after the Apply; open ones keep what they opened with until they end. Nothing
  here cuts a connection;
- **of two classes that match one connection, the lower sequence wins** - pf applies every match
  rule that matches, in order, and the last DSCP set stays (`pf.c:5039-5056`), so the classes are
  registered highest sequence first. Of two with the same sequence, the one first in the list wins;
- **the IP version of a class is what its addresses allow** - an IPv4 source with an IPv6 destination
  is no rule at all, because pfctl refuses such a rule (`parse.y:6346-6351`, `6533`) and with it the
  whole rule set, every rule of the owner's too. The page refuses such a class at the save, and the
  hook writes no rule for one written by other means, nor for a port without TCP or UDP
  (`parse.y:5309`), nor for an interface or address field it cannot read, and says why in the system
  log (`Traffic Priority:`) and on the page;
- **a class narrows what it marks** - by an interface, a source, a destination, a port or the DSCP a
  connection arrives with. One with none of them would mark every connection, both ways, every
  download among them, and networks upstream and Wi-Fi take a mark such as EF for voice. The page
  refuses such a class at the save, and the hook writes no rule for one written by other means;
- **nothing that would break the rules file is written** - config.xml can be written by other means
  than the page, and OPNsense writes some fields as they are given: a port it cannot map into a
  `#debug:` comment and into the rule it comments out, the description at the end of the line. So a
  port is taken as a number, a range whose first port is not above its second, a name or an alias of
  ports, and nothing else: not with a line break in it, which would start a line pf loads, nor an
  alias of addresses, which 26.7 to 26.7.7 write as a port, nor a range the wrong way round, which
  26.7 to 26.7.5 write as it is (`parse.y:3836-3840`) - pfctl refuses either, and with it the whole
  rule set. Nor a description ending in a backslash, which pfctl takes as joining the next line to
  it, a comment's too (`parse.y:6806-6814`, `6882-6883`), so that the next rule would quietly not be
  loaded. The page refuses each at the save - a class is read whole when any field of it changes -
  and the hook writes no rule for one written by other means;
- **"Arriving with DSCP" is pf's `tos`** - matched on the packet that opens the connection, its ECN
  bits aside. pf cannot match 0, which it takes for no DSCP asked (`pf.c:5805`), so Best Effort is
  not offered there.

**Why a match rule, and not the normalization rule os-xgs-npu measured with.** A plugin cannot add a
normalization rule: OPNsense writes the owner's own there and nothing else (`filter.inc:468-546`).
And pf reads those rules at the IP header without their ports, the first that matches setting its
mark (`pf_norm.c:1167-1203`, `1321-1354`): read in the source, a normalization rule with a port and a
TOS / DSCP marks every connection that matches the rest of it, whatever its port. Not measured. A
match rule checks its ports (`pf.c:5763-5770`).

**The key the mark is written with.** OPNsense 26.7.9 has one of its own for pf's scrub options on a
rule (`scrub`, `FilterRule.php:58` there). 26.7 to 26.7.8 have none, and the plugin writes the same
text through the key those versions write as given (`dn`, `FilterRule.php:69`; set by OPNsense only
from a Shaper rule's pipe or queue, which a class never has). Which one is used is read from the
running OPNsense's own rule class; where neither is there, no class is applied and the system log
says so. The checks write every sample class out with the rule classes of both OPNsense 26.7 and
26.7.9 ([What is tested](#what-is-tested)).

## On a Sophos XGS

What [os-xgs-npu](https://github.com/AbdelmonemAwad/os-xgs-npu) measured, with OPNsense's
normalization rule rather than with this plugin's rules:

- **an IPv4 connection in hardware keeps pf's mark** - since 2026-10-24 both drivers give a
  connection they make the DSCP pf's state carries, on the XGS 3300 and the XGS 136
  ([flow-dscp-2026-10-24](https://github.com/AbdelmonemAwad/os-xgs-npu/blob/main/docs/measurements/flow-dscp-2026-10-24.md)).
  The drivers read the state's actions, the same field a match rule fills (`octep_pf_tos_scan`,
  `npuep_pf_tos_scan`);
- **a marked IPv6 connection stays with the host** - the fast path does not write an IPv6 traffic
  class, on either appliance, so pf writes it there and the connection is not forwarded in hardware
  ([flow-dscp6-2026-10-24](https://github.com/AbdelmonemAwad/os-xgs-npu/blob/main/docs/measurements/flow-dscp6-2026-10-24.md)).
  That is why a class is IPv4 unless told otherwise;
- **the switch queues every frame from the coprocessor in queue 0** - marked or not, whatever port 0's
  ingress map says
  ([qsched-2026-10-25](https://github.com/AbdelmonemAwad/os-xgs-npu/blob/main/docs/measurements/qsched-2026-10-25.md)),
  and the connection's priority bit and the coprocessor's QoS commands have no effect with its
  firmware ([port-qos-2026-10-24](https://github.com/AbdelmonemAwad/os-xgs-npu/blob/main/docs/measurements/port-qos-2026-10-24.md)).
  So a mark alone moves no frame ahead of another in the switch yet: the page says "not measured
  yet" for the switch queue of every class.

A connection in hardware adds no more to the packets and bytes pf counts for its class; its state
stays counted while it is open.

## Not yet, and why

- **the switch's queues** - putting a marked frame in its own queue, and scheduling the queues, is
  the next part: os-xgs-npu's switch tool first, then measured on a lab appliance, the XGS 136 only
  after the XGS 3300. Until then nothing of the switch is written, and the page says "not measured
  yet".
- **these rules on an appliance** - nothing here has been installed: the rules pfctl loads, the page,
  the mark in hardware with a match rule instead of a normalization rule (the state field is the
  same, `act.set_tos`, read in the source, not measured), and the removal.
- **the firewall's own outgoing connections** - a class matches where connections come in, so a
  connection the firewall opens itself (its own DNS queries, say) is not marked; one opened to it -
  the GUI, SSH - is, both ways.
- **IPv6 in hardware** - see above: a marked IPv6 connection stays with the host.
- **following Firewall: Shaper, a guaranteed minimum, users and applications** - later parts, after
  the queues.

## What is tested

On 2026-11-17, from this branch, nothing installed on any firewall:

- **the rules** - `tools/test-rules.php`, 112 checks, run with OPNsense's own Plugin, FilterRule, Rule
  and Util of every release from 26.7 to 26.7.9, from opnsense/core's tags, and of opnsense/core's
  main branch of that day, under PHP 8.5. For sample classes it checks the line OPNsense
  writes - match, in, never quick, no state, no reply-to, the DSCP's ECN bits clear, the label -
  against pfctl's grammar; one rule per interface and IP version; priority 0 ahead of OPNsense's own;
  the sequence's order, an unreadable one first; no rule, and the reason in the log, for an address
  pair of two versions, a port without TCP or UDP, an interface or address field it cannot read, a
  port holding a line break, an alias of addresses or a range the wrong way round, a description
  ending in a backslash, a class that narrows nothing, a DSCP out of range, 0 to match, a class
  without an ID; nothing while off, the default; a rule OPNsense refuses leaving the reload and the
  other classes alone; and the key each release writes the mark with;
- **the model** - `tools/test-mvc.php`, 31 checks, with stand-ins for OPNsense's MVC base: each of
  those refusals at the save, on the field it concerns, a class read whole when any field of it
  changed, and the message of OPNsense's own field type kept where it gave one;
- **the page's numbers** - `tools/test-status.py`, 17 checks: `status.py` reading a `rules.debug` and
  a `pfctl -v -s rules` as OPNsense and pfctl write them, by each class's label;
- **the self-update** - `tools/test-self-update.py`, 45 checks, as os-blocklists has it;
- **the rest of the checks** - every installed file removed by the uninstaller
  (`tools/check-uninstall.sh`), `php -l`, `py_compile` and pyflakes, `sh -n`, XML and JSON, nothing
  private, no Arabic in the code, the page kit.

30 behaviours those tests cover were taken out in turn, on a copy, and the tests failed on each.

Not tested: anything on a firewall.

## Installation

It is not in the OPNsense plugin repository, so there is no `pkg install os-trafficpriority`, and
there is no release yet.

**From a checkout** of this repository, on the firewall, as root:

```sh
sh install/install.sh
```

It checks the PHP and the rules hook with `php -l` and the Python with `py_compile` before anything
is copied, then copies `src/` onto `/usr/local`, puts the page in the menu (`place-menu.sh`: XGS with
os-xgs-npu, Firewall without), reloads the filter and records the commit for the self-update. Safe to
run again: the settings in config.xml are kept. Nothing is marked until Enabled is on and a class is
applied.

`sh install/uninstall.sh` removes the plugin, reloads the filter, and says whether pf still holds any
of its rules - none, when the reload loaded; when it did not, OPNsense loads the rule set before it
again, these rules with it, and the script says so and exits 1. The settings stay in config.xml. A
connection marked before keeps its mark until it ends.

**From a package**, once there is a release: `tools/make-package.sh` builds it on a firewall, and
`release.yml` in a FreeBSD virtual machine for each release, as os-blocklists does. `pkg delete
os-trafficpriority` takes the rules hook with the files and reloads the filter, so the rules leave
pf.

## Updates

As os-blocklists: taken by hand, to this repository's **releases** - from **XGS: Updates**, its
*Plugins* tab, where an os-xgs-npu that lists this plugin is installed, or by running
`/usr/local/opnsense/scripts/trafficpriority/self-update.py` (`check` to ask). A release is installed
only as its owner signed it (`release.json` and its Ed25519 signature, the public key in
`release-keys/`), only forward, by the `install/install.sh` it carries. No cron entry runs it.

## Where it fits

It is one part of the [os-xgs-npu](https://github.com/AbdelmonemAwad/os-xgs-npu) project, which puts OPNsense on Sophos XGS hardware, and works the way its other plugins do: changes by pull request, a release installed from **XGS: Updates**, its Arabic in [opnsense-arabic](https://github.com/AbdelmonemAwad/opnsense-arabic)'s catalogue. It installs the same on a plain OPNsense, where pf alone marks the connections and the page says so.

## Licence

BSD 2-Clause - see [LICENSE](LICENSE).
