# Cross-class gadget graph: `joomla-graph`

Root `lab-joomla/webroot` — 5047 classes, 23687 methods, 272 entries, 12402 visited nodes, 80 paths.

Typed property/interface expansion via PHP-Parser facts. This finds chains the same-method sweep cannot; it still does not prove reachability or attacker control.

## Top paths

| score | sink | depth | chain | sink at |
|---|---|---|---|---|
| 90 | terminal | 0 | `FileLogger::__destruct -> shell_exec()` | api/endpoint.php:22 |
| 61 | dispatch | 3 | `Mail::__destruct -> Mail::smtpClose -> SMTP::connected -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 61 | dispatch | 3 | `Mail::__destruct -> Mail::smtpClose -> SMTP::close -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 61 | dispatch | 3 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::connected -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 61 | dispatch | 3 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::close -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 61 | dispatch | 3 | `PHPMailer::__destruct -> Mail::smtpClose -> SMTP::connected -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 61 | dispatch | 3 | `PHPMailer::__destruct -> Mail::smtpClose -> SMTP::close -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 58 | dispatch | 4 | `Mail::__destruct -> Mail::smtpClose -> SMTP::connected -> SMTP::close -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 58 | dispatch | 4 | `Mail::__destruct -> Mail::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 58 | dispatch | 4 | `Mail::__destruct -> Mail::smtpClose -> SMTP::quit -> SMTP::close -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 58 | dispatch | 4 | `Mail::__destruct -> Mail::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::client_send -> call_user_func_array()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:1192 |
| 58 | dispatch | 4 | `Mail::__destruct -> Mail::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::get_lines -> call_user_func_array()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:1297 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::connected -> SMTP::close -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::quit -> SMTP::close -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> Mail::smtpClose -> SMTP::connected -> SMTP::close -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> Mail::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> Mail::smtpClose -> SMTP::quit -> SMTP::close -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::client_send -> call_user_func_array()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:1192 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::get_lines -> call_user_func_array()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:1297 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> Mail::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::client_send -> call_user_func_array()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:1192 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> Mail::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::get_lines -> call_user_func_array()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:1297 |
| 55 | dispatch | 5 | `Mail::__destruct -> Mail::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::connected -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 55 | dispatch | 5 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::connected -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 55 | dispatch | 5 | `PHPMailer::__destruct -> Mail::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::connected -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 52 | dispatch | 6 | `Mail::__destruct -> Mail::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::connected -> SMTP::close -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 52 | dispatch | 6 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::connected -> SMTP::close -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 52 | dispatch | 6 | `PHPMailer::__destruct -> Mail::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::connected -> SMTP::close -> SMTP::edebug -> call_user_func()` | libraries/vendor/phpmailer/phpmailer/src/SMTP.php:299 |
| 50 | file | 0 | `FileLogger::__destruct -> file_put_contents()` | api/endpoint.php:26 |
| 50 | file | 0 | `ZIPExtraction::__wakeup -> fopen()` | administrator/components/com_joomlaupdate/extract.php:501 |

## Reproduce

```sh
scripts/gadget_graph.sh lab-joomla/webroot --label joomla-graph
```
