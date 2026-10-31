# Cross-class gadget graph: `wordpress-graph`

Root `lab-wp-zendmm/webroot` — 845 classes, 7714 methods, 50 entries, 462 visited nodes, 35 paths.

Typed property/interface expansion via PHP-Parser facts. This finds chains the same-method sweep cannot; it still does not prove reachability or attacker control.

## Top paths

| score | sink | depth | chain | sink at |
|---|---|---|---|---|
| 100 | reentry | 0 | `WP_UAF_Gadget::__destruct -> unserialize()` | wp-content/mu-plugins/uaf-harness.php:33 |
| 100 | reentry | 0 | `WP_VD_Gadget::__destruct -> unserialize()` | wp-content/mu-plugins/vd-harness.php:46 |
| 90 | terminal | 0 | `FileLogger::__destruct -> shell_exec()` | api/endpoint.php:22 |
| 70 | dispatch | 0 | `WP_HTML_Token::__destruct -> call_user_func()` | wp-includes/html-api/class-wp-html-token.php:114 |
| 61 | dispatch | 3 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::connected -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 61 | dispatch | 3 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::close -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 61 | dispatch | 3 | `PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::connected -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 61 | dispatch | 3 | `PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::close -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 61 | dispatch | 3 | `WP_PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::connected -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 61 | dispatch | 3 | `WP_PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::close -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::connected -> SMTP::close -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::quit -> SMTP::close -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::connected -> SMTP::close -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::quit -> SMTP::close -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::client_send -> call_user_func_array()` | wp-includes/PHPMailer/SMTP.php:1253 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::get_lines -> call_user_func_array()` | wp-includes/PHPMailer/SMTP.php:1358 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::client_send -> call_user_func_array()` | wp-includes/PHPMailer/SMTP.php:1253 |
| 58 | dispatch | 4 | `PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::get_lines -> call_user_func_array()` | wp-includes/PHPMailer/SMTP.php:1358 |
| 58 | dispatch | 4 | `WP_PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::connected -> SMTP::close -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 58 | dispatch | 4 | `WP_PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 58 | dispatch | 4 | `WP_PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::quit -> SMTP::close -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 58 | dispatch | 4 | `WP_PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::client_send -> call_user_func_array()` | wp-includes/PHPMailer/SMTP.php:1253 |
| 58 | dispatch | 4 | `WP_PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::get_lines -> call_user_func_array()` | wp-includes/PHPMailer/SMTP.php:1358 |
| 55 | dispatch | 5 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::connected -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 55 | dispatch | 5 | `PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::connected -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 55 | dispatch | 5 | `WP_PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::connected -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 52 | dispatch | 6 | `PHPMailer::__destruct -> PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::connected -> SMTP::close -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |
| 52 | dispatch | 6 | `PHPMailer::__destruct -> WP_PHPMailer::smtpClose -> SMTP::quit -> SMTP::sendCommand -> SMTP::connected -> SMTP::close -> SMTP::edebug -> call_user_func()` | wp-includes/PHPMailer/SMTP.php:301 |

## Reproduce

```sh
scripts/gadget_graph.sh lab-wp-zendmm/webroot --label wordpress-graph
```
