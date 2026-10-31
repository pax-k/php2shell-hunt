"""Per-application adapters.

Each adapter knows:
  - how to detect the application over HTTP (WP / Joomla / generic lab),
  - the lab endpoint layout it assumes (write/read/LFI/probe paths),
  - what its chain-support notes are.

There is deliberately NO static port -> flags/container registry: adapters
provide endpoint DEFAULTS only, and the driver re-verifies every
precondition live (see fingerprint.py / strategies.py / dockerutil.py). The
instrumented-lab container is discovered dynamically at run time.
"""

from dataclasses import dataclass, field


@dataclass
class AppAdapter:
    key: str
    label: str
    # detection marker(s) looked up in the HTTP body
    markers: tuple = ()
    detect_path: str = "/"
    # generic-lab endpoint layout assumptions (defaults; re-verified live)
    fingerprint_path: str = "/index.php"
    write_path: str = "/app/upload.php"       # php_serialize dir
    read_path: str = "/api/endpoint.php"      # php dir + FileLogger gadget
    lfi_path: str = "/lfi.php"                # Chain A LFI
    handler_probe: str = "/api/handler_probe.php"
    obj_probe: str = "/obj_probe.php"         # rung-5b calibration endpoint
    gadget_banner: str = "gadget class available"
    notes: str = ""
    extra: dict = field(default_factory=dict)


GENERIC = AppAdapter(
    key="generic",
    label="generic PHP application (lab)",
    markers=("upload_progress",),
    detect_path="/index.php",
)

WORDPRESS = AppAdapter(
    key="wordpress",
    label="WordPress",
    markers=("user_login", "wp-submit"),
    detect_path="/wp-login.php",
    fingerprint_path="/index.php",
    # stock WP has no LFI / gadget scaffolding; these are only present in
    # the instrumented lab-wp-zendmm webroot (api/, app/, obj_probe.php).
    notes="stock WP carries no LFI/gadget preconditions; only the "
          "instrumented lab (lab-wp-zendmm) supports the chains here",
)

JOOMLA = AppAdapter(
    key="joomla",
    label="Joomla",
    markers=("Joomla",),
    detect_path="/administrator/",
    fingerprint_path="/sysinfo.php",  # lab-provided banner (lab-joomla)
    notes="lab-joomla/ (php:8.2-fpm + Joomla 5.4.10 + chain scaffolding)",
)

ADAPTERS = {a.key: a for a in (GENERIC, WORDPRESS, JOOMLA)}