# lab-wp-zendmm - FPM/WordPress `var_destroy` harness

**LAB-ONLY.** Loopback only, fixed benign command `id>/tmp/vd 2>&1`.

The PHP image is built locally from this directory's `Dockerfile` (compose uses
`build: .` and tags it `php-wp-zendmm-lab:local`). `setup.sh` rebuilds the
webroot: it copies the chain endpoints from `../lab-chain-a/webroot/` and
installs a WordPress core. Neither WordPress nor the vendor tree is tracked in
git.

`uaf-harness/` models a plugin-level double-`unserialize` sink. It is a lab
model, not a plugin, and must not be installed on a live site.

Receipt: `poc/verify_var_destroy_wp.py` returns `502` and the FPM log shows
`[UAFDBG] INIT lock=0 level=2` then `child exited on signal 11 (SIGSEGV)`. That
is a per-request denial of service for a plugin with this shape, not a
WordPress-core RCE. See `docs/VAR_DESTROY_UAF.md` and
`docs/RESPONSIBLE_PUBLICATION.md`.
