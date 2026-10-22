# Traffic Priority for OPNsense

Strict priority for chosen traffic - voice, games, the firewall's own management - applied where that traffic actually flows: in the queues of a Sophos XGS's coprocessor and of its switch, which forwarded traffic never leaves.

> **Planned - nothing here runs yet.** This repository was opened on 2026-10-22 to hold
> Traffic Priority as a plugin of its own. No code has been written or moved into it, and there is no
> release.

## What it is to do

- priority classes for chosen traffic, by port, address or DSCP;
- the classes applied in the coprocessor's and the switch's own queues;
- a page in the XGS section of OPNsense's menu, with what each class carried.

## Where it fits

It is one part of the [os-xgs-npu](https://github.com/AbdelmonemAwad/os-xgs-npu) project, which puts OPNsense on Sophos XGS hardware, and works the way its other plugins do: changes by pull request, a release installed from **XGS: Updates**, its Arabic in [opnsense-arabic](https://github.com/AbdelmonemAwad/opnsense-arabic)'s catalogue.

## Licence

BSD 2-Clause - see [LICENSE](LICENSE).
