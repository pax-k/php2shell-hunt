<?php
/* LAB-ONLY prime endpoint: accept the upload-progress POST and do NOT call
 * session_start(). The rfc1867 hook initialises the session itself and writes
 * the progress record under the configured php_serialize handler, leaving one
 * dummy record in /tmp/sessions/sess_<sid>. The exploit request then adds a
 * second record; the php decoder's record loop is what makes 8.4.27's real
 * var_destroy dtor (inv=2) appear.
 */
echo "prime ok\n";
