<?php
/* LAB-ONLY prime endpoint for the Redis store: accept the upload-progress POST
 * and do NOT call session_start(). The rfc1867 hook initialises the session
 * itself and writes the progress record with the configured php_serialize
 * handler. Kept separate from probe.php so the probe never writes.
 */
echo "prime ok\n";
