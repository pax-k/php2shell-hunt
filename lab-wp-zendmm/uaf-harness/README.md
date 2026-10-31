# uaf-harness — LAB-ONLY WordPress mu-plugin

Models the two conditions the `var_destroy` patch-gap needs inside a real
WordPress/FPM worker:

1. **sink** — `unserialize(wp_unslash($_POST['d']))` on user input;
2. **gadget** — `WP_UAF_Gadget::__destruct()` does a same-size spray and then
   re-enters `unserialize('R:1020;')`.

`setup.sh` copies this file to `webroot/wp-content/mu-plugins/`, so it loads
without activation.

```sh
(cd lab-wp-zendmm && ./setup.sh && docker compose up -d)
python3 poc/verify_var_destroy_wp.py --target http://127.0.0.1:18095
# -> 502 + "child ... exited on signal 11 (SIGSEGV)" = per-request DoS
```

This is **not** a WordPress core vulnerability and not a real plugin. It is a
lab model of a plugin-level double-unserialize bug; do not install it on a
live site. See `docs/VAR_DESTROY_UAF.md` for the analysis and the
`allowed_classes=false` mitigation.
