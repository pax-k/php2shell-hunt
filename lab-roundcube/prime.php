<?php
/* LAB-ONLY prime endpoint (Roundcube lab): accept the upload-progress POST and
 * do NOT call session_start(). The rfc1867 hook initialises the session itself
 * and writes the progress record under the configured php_serialize handler,
 * leaving one record in /tmp/sessions/sess_<sid>. The exploit request to
 * Roundcube's index.php then appends the real record; 8.4.27's UAF dtor only
 * appears on the second record.
 *
 * This file is bind-mounted into the Roundcube webroot; the route never enters
 * Roundcube's bootstrap.
 */
echo "prime ok\n";
