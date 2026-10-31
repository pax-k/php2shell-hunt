# Gadget sweep: `roundcube`

Root `lab-roundcube/roundcubemail-1.6.11` — 582 PHP files, 79 magic methods, 349 candidates, 1 re-entry.

Candidate generation only. A hit means *read this next*, not *exploitable*; dynamic reachability and the lab decide that.

## Ranked candidates

| score | kind | class | method | sinks | where |
|---|---|---|---|---|---|
| 100 | reentry | CachePurge | __destruct | file, unserialize | lab-roundcube/roundcubemail-1.6.11/plugins/vd115560/vd115560.php:73 |
| 90 | terminal | VdSimple | __destruct | terminal | lab-roundcube/roundcubemail-1.6.11/plugins/vd115560/vd115560.php:51 |
| 80 | dispatch | PEAR | __call | dispatch | lab-roundcube/roundcubemail-1.6.11/vendor/pear/pear-core-minimal/src/PEAR.php:216 |
| 80 | dispatch | PEAR | __callStatic | dispatch | lab-roundcube/roundcubemail-1.6.11/vendor/pear/pear-core-minimal/src/PEAR.php:229 |
| 60 | file | rcmail_attachment_handler | __destruct | file | lab-roundcube/roundcubemail-1.6.11/program/include/rcmail_attachment_handler.php:123 |
| 60 | file | rcmail_sendmail | __destruct | file | lab-roundcube/roundcubemail-1.6.11/program/include/rcmail_sendmail.php:82 |
| 45 | terminal | markasjunk_cmd_learn | _do_salearn | file, terminal | lab-roundcube/roundcubemail-1.6.11/plugins/markasjunk/drivers/cmd_learn.php:41 |
| 45 | dispatch | markasjunk_email_learn | _do_emaillearn | dispatch, file | lab-roundcube/roundcubemail-1.6.11/plugins/markasjunk/drivers/email_learn.php:41 |
| 45 | terminal | rcube_chpasswd_password | save | file, terminal | lab-roundcube/roundcubemail-1.6.11/plugins/password/drivers/chpasswd.php:32 |
| 45 | terminal | rcube_dbmail_password | save | terminal | lab-roundcube/roundcubemail-1.6.11/plugins/password/drivers/dbmail.php:35 |
| 45 | terminal | rcube_expect_password | save | file, terminal | lab-roundcube/roundcubemail-1.6.11/plugins/password/drivers/expect.php:45 |
| 45 | terminal | rcube_kpasswd_password | save | file, terminal | lab-roundcube/roundcubemail-1.6.11/plugins/password/drivers/kpasswd.php:20 |
| 45 | terminal | rcube_ldap_ppolicy_password | save | file, terminal | lab-roundcube/roundcubemail-1.6.11/plugins/password/drivers/ldap_ppolicy.php:17 |
| 45 | terminal | rcube_pw_usermod_password | save | file, terminal | lab-roundcube/roundcubemail-1.6.11/plugins/password/drivers/pw_usermod.php:33 |
| 45 | terminal | rcube_sasl_password | save | file, terminal | lab-roundcube/roundcubemail-1.6.11/plugins/password/drivers/sasl.php:36 |
| 45 | terminal | rcube_smb_password | save | file, terminal | lab-roundcube/roundcubemail-1.6.11/plugins/password/drivers/smb.php:42 |
| 45 | terminal | rcube_virtualmin_password | save | terminal | lab-roundcube/roundcubemail-1.6.11/plugins/password/drivers/virtualmin.php:34 |
| 45 | terminal | password | hash_password | file, terminal | lab-roundcube/roundcubemail-1.6.11/plugins/password/password.php:526 |
| 45 | dispatch | rcmail_action_contacts_index | contact_form | dispatch | lab-roundcube/roundcubemail-1.6.11/program/actions/contacts/index.php:783 |
| 45 | dispatch | rcmail_action_mail_bounce | run | dispatch | lab-roundcube/roundcubemail-1.6.11/program/actions/mail/bounce.php:30 |
| 45 | dispatch | rcmail_action_mail_send | run | dispatch | lab-roundcube/roundcubemail-1.6.11/program/actions/mail/send.php:28 |
| 45 | terminal | rcmail_install | vendor_dir_untouched | terminal | lab-roundcube/roundcubemail-1.6.11/program/include/rcmail_install.php:929 |
| 45 | terminal | rcmail_output_html | xml_command | autoload, dispatch, terminal | lab-roundcube/roundcubemail-1.6.11/program/include/rcmail_output_html.php:1333 |
| 45 | dispatch | rcube | shutdown | dispatch | lab-roundcube/roundcubemail-1.6.11/program/lib/Roundcube/rcube.php:1089 |
| 45 | terminal | rcube | exec | terminal | lab-roundcube/roundcubemail-1.6.11/program/lib/Roundcube/rcube.php:1224 |

## Re-entry candidates (magic -> unserialize)

| class | method | where | evidence |
|---|---|---|---|
| CachePurge | __destruct | lab-roundcube/roundcubemail-1.6.11/plugins/vd115560/vd115560.php:73 | unserialize('R:' . $ref . ';'); file_put_contents('/tmp/meas_pid', getmypid()); file_put_contents('/tmp/meas_pid', getmypid()) |

## Magic method inventory

| magic method | count |
|---|---|
| __toString | 23 |
| __destruct | 21 |
| __invoke | 9 |
| __get | 6 |
| __clone | 4 |
| __wakeup | 4 |
| __call | 4 |
| __sleep | 3 |
| __callStatic | 3 |
| __serialize | 1 |
| __unserialize | 1 |

| class | method | where |
|---|---|---|
| debug_logger | __destruct | lab-roundcube/roundcubemail-1.6.11/plugins/debug_logger/debug_logger.php:153 |
| runlog | __destruct | lab-roundcube/roundcubemail-1.6.11/plugins/debug_logger/runlog/runlog.php:204 |
| rcube_sieve | __destruct | lab-roundcube/roundcubemail-1.6.11/plugins/managesieve/lib/Roundcube/rcube_sieve.php:119 |
| VdSimple | __destruct | lab-roundcube/roundcubemail-1.6.11/plugins/vd115560/vd115560.php:51 |
| VdSimple | __destruct | lab-roundcube/roundcubemail-1.6.11/plugins/vd115560/vd115560.php:51 |
| CachePurge | __destruct | lab-roundcube/roundcubemail-1.6.11/plugins/vd115560/vd115560.php:73 |
| CachePurge | __destruct | lab-roundcube/roundcubemail-1.6.11/plugins/vd115560/vd115560.php:73 |
| CachePurge | __destruct | lab-roundcube/roundcubemail-1.6.11/plugins/vd115560/vd115560.php:73 |
| CachePurge | __destruct | lab-roundcube/roundcubemail-1.6.11/plugins/vd115560/vd115560.php:73 |
| CachePurge | __destruct | lab-roundcube/roundcubemail-1.6.11/plugins/vd115560/vd115560.php:73 |
| rcmail_attachment_handler | __destruct | lab-roundcube/roundcubemail-1.6.11/program/include/rcmail_attachment_handler.php:123 |
| rcmail_attachment_handler | __destruct | lab-roundcube/roundcubemail-1.6.11/program/include/rcmail_attachment_handler.php:123 |
| rcmail_sendmail | __destruct | lab-roundcube/roundcubemail-1.6.11/program/include/rcmail_sendmail.php:82 |
| rcmail_sendmail | __destruct | lab-roundcube/roundcubemail-1.6.11/program/include/rcmail_sendmail.php:82 |
| rcube_db_param | __toString | lab-roundcube/roundcubemail-1.6.11/program/lib/Roundcube/db/param.php:50 |
| rcube_imap | __get | lab-roundcube/roundcubemail-1.6.11/program/lib/Roundcube/rcube_imap.php:100 |
| rcube_message_part | __clone | lab-roundcube/roundcubemail-1.6.11/program/lib/Roundcube/rcube_message_part.php:128 |
| rcube_output | __get | lab-roundcube/roundcubemail-1.6.11/program/lib/Roundcube/rcube_output.php:51 |
| rcube_result_multifolder | __sleep | lab-roundcube/roundcubemail-1.6.11/program/lib/Roundcube/rcube_result_multifolder.php:321 |
| rcube_result_multifolder | __wakeup | lab-roundcube/roundcubemail-1.6.11/program/lib/Roundcube/rcube_result_multifolder.php:340 |

## Stream / session markers

| file | line | text |
|---|---|---|
| config/config.inc.php | 9 | * session.upload_progress hook (server side: files + php_serialize) is the |
| plugins/vd115560/vd115560.php | 11 | *      ini_set('session.serialize_handler', 'php') (stock Roundcube only |
| plugins/vd115560/vd115560.php | 31 | rc_vd_log('plugin-load handler=' . ini_get('session.serialize_handler') |
| plugins/vd115560/vd115560.php | 36 | @ini_set('session.serialize_handler', 'php'); |
| plugins/vd115560/vd115560.php | 37 | rc_vd_log('handler-switched handler=' . ini_get('session.serialize_handler')); |
| plugins/vd115560/vd115560.php | 40 | rc_vd_log('handler-switch-DISABLED handler=' . ini_get('session.serialize_handler')); |
| program/lib/Roundcube/rcube_session.php | 116 | ini_set('session.serialize_handler', 'php'); |

## Semgrep (candidate files only)

| rule | file | line | message |
|---|---|---|---|
| php-session-handler-switch | lab-roundcube/roundcubemail-1.6.11/plugins/vd115560/vd115560.php | 36 | session serialization handler is switched at runtime |
| php-magic-terminal | lab-roundcube/roundcubemail-1.6.11/plugins/vd115560/vd115560.php | 54 | magic method reaches a terminal command sink |
| php-magic-reentry | lab-roundcube/roundcubemail-1.6.11/plugins/vd115560/vd115560.php | 108 | magic method re-enters deserialization |
| php-session-handler-switch | lab-roundcube/roundcubemail-1.6.11/program/lib/Roundcube/rcube_session.php | 116 | session serialization handler is switched at runtime |

## Tools

- **ast-grep**: 634 matches
- **ctags**: ok
- **semgrep**: 4 findings
- **rg**: ok

## Reproduce

```sh
scripts/gadget_sweep.sh lab-roundcube/roundcubemail-1.6.11 --label roundcube
```
