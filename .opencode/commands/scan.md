---
description: Run the loopback PHP session scanner against one target or a file of targets.
---

Run:

```sh
scripts/scan.sh $ARGUMENTS
```

If no target is supplied, ask for one. The target must be `localhost`, `127.*`,
or `::1`, and the lab must use stock image defaults with no `php.ini` mount.
`--active` is destructive and only allowed against a disposable lab.

Report the verdict, exit code, and the evidence tier that produced it. Do not
describe a scanner verdict as exploitation or as progress toward RCE by itself.
