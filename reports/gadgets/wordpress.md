# Gadget sweep: `wordpress`

Root `lab-wp-zendmm/webroot` — 1521 PHP files, 179 magic methods, 896 candidates, 2 re-entry.

Candidate generation only. A hit means *read this next*, not *exploitable*; dynamic reachability and the lab decide that.

## Ranked candidates

| score | kind | class | method | sinks | where |
|---|---|---|---|---|---|
| 100 | reentry | WP_UAF_Gadget | __destruct | unserialize | lab-wp-zendmm/webroot/wp-content/mu-plugins/uaf-harness.php:25 |
| 100 | reentry | WP_VD_Gadget | __destruct | unserialize | lab-wp-zendmm/webroot/wp-content/mu-plugins/vd-harness.php:36 |
| 90 | terminal | FileLogger | __destruct | file, terminal | lab-wp-zendmm/webroot/api/endpoint.php:16 |
| 80 | dispatch | WpOrg\Requests\Iri | __set | autoload, dispatch | lab-wp-zendmm/webroot/wp-includes/Requests/src/Iri.php:163 |
| 80 | dispatch | WpOrg\Requests\Iri | __unset | autoload, dispatch | lab-wp-zendmm/webroot/wp-includes/Requests/src/Iri.php:240 |
| 80 | dispatch | SimplePie\IRI | __set | autoload, dispatch | lab-wp-zendmm/webroot/wp-includes/SimplePie/src/IRI.php:120 |
| 80 | dispatch | SimplePie\IRI | __unset | autoload, dispatch | lab-wp-zendmm/webroot/wp-includes/SimplePie/src/IRI.php:197 |
| 80 | dispatch | WP_HTML_Token | __destruct | autoload, dispatch | lab-wp-zendmm/webroot/wp-includes/html-api/class-wp-html-token.php:112 |
| 45 | dispatch | - | <file> | autoload, dispatch, file | lab-wp-zendmm/webroot/wp-admin/admin.php:35 |
| 45 | dispatch | - | wp_ajax_save_widget | autoload, dispatch | lab-wp-zendmm/webroot/wp-admin/includes/ajax-actions.php:2395 |
| 45 | dispatch | - | wp_ajax_wp_privacy_export_personal_data | autoload, dispatch | lab-wp-zendmm/webroot/wp-admin/includes/ajax-actions.php:4984 |
| 45 | dispatch | - | wp_ajax_wp_privacy_erase_personal_data | autoload, dispatch | lab-wp-zendmm/webroot/wp-admin/includes/ajax-actions.php:5174 |
| 45 | terminal | WP_Debug_Data | get_wp_media | autoload, terminal | lab-wp-zendmm/webroot/wp-admin/includes/class-wp-debug-data.php:630 |
| 45 | dispatch | WP_Screen | render_screen_meta | dispatch | lab-wp-zendmm/webroot/wp-admin/includes/class-wp-screen.php:789 |
| 45 | dispatch | WP_Site_Health | perform_test | dispatch | lab-wp-zendmm/webroot/wp-admin/includes/class-wp-site-health.php:182 |
| 45 | dispatch | - | _wp_handle_upload | dispatch, file | lab-wp-zendmm/webroot/wp-admin/includes/file.php:809 |
| 45 | dispatch | - | wp_iframe | dispatch | lab-wp-zendmm/webroot/wp-admin/includes/media.php:553 |
| 45 | dispatch | - | edit_post | autoload, dispatch | lab-wp-zendmm/webroot/wp-admin/includes/post.php:269 |
| 45 | dispatch | - | wp_widget_control | dispatch | lab-wp-zendmm/webroot/wp-admin/includes/widgets.php:190 |
| 45 | dispatch | - | <file> | autoload, dispatch, file | lab-wp-zendmm/webroot/wp-admin/widgets-form.php:175 |
| 45 | terminal | getid3_lib | getFileSizeSyscall | autoload, terminal | lab-wp-zendmm/webroot/wp-includes/ID3/getid3.lib.php:1789 |
| 45 | terminal | getID3 | __construct | file, terminal | lab-wp-zendmm/webroot/wp-includes/ID3/getid3.php:399 |
| 45 | terminal | getID3 | getHashdata | file, terminal | lab-wp-zendmm/webroot/wp-includes/ID3/getid3.php:1771 |
| 45 | dispatch | IXR_Server | call | autoload, dispatch | lab-wp-zendmm/webroot/wp-includes/IXR/class-IXR-server.php:87 |
| 45 | dispatch | PHPMailer\PHPMailer\PHPMailer | edebug | autoload, dispatch | lab-wp-zendmm/webroot/wp-includes/PHPMailer/PHPMailer.php:912 |

## Re-entry candidates (magic -> unserialize)

| class | method | where | evidence |
|---|---|---|---|
| WP_UAF_Gadget | __destruct | lab-wp-zendmm/webroot/wp-content/mu-plugins/uaf-harness.php:25 | unserialize($this->p) |
| WP_VD_Gadget | __destruct | lab-wp-zendmm/webroot/wp-content/mu-plugins/vd-harness.php:36 | unserialize('R:1020;') |

## Magic method inventory

| magic method | count |
|---|---|
| __toString | 25 |
| __destruct | 23 |
| __get | 22 |
| __set | 20 |
| __isset | 19 |
| __wakeup | 17 |
| __clone | 15 |
| __unset | 13 |
| __call | 12 |
| __sleep | 5 |
| __debugInfo | 3 |
| __unserialize | 2 |
| __callStatic | 2 |
| __serialize | 1 |

| class | method | where |
|---|---|---|
| FileLogger | __destruct | lab-wp-zendmm/webroot/api/endpoint.php:16 |
| FileLogger | __destruct | lab-wp-zendmm/webroot/api/endpoint.php:16 |
| FileLogger | __destruct | lab-wp-zendmm/webroot/api/endpoint.php:16 |
| WP_Filesystem_FTPext | __destruct | lab-wp-zendmm/webroot/wp-admin/includes/class-wp-filesystem-ftpext.php:892 |
| WP_Filesystem_ftpsockets | __destruct | lab-wp-zendmm/webroot/wp-admin/includes/class-wp-filesystem-ftpsockets.php:781 |
| WP_List_Table | __get | lab-wp-zendmm/webroot/wp-admin/includes/class-wp-list-table.php:196 |
| WP_List_Table | __set | lab-wp-zendmm/webroot/wp-admin/includes/class-wp-list-table.php:219 |
| WP_List_Table | __isset | lab-wp-zendmm/webroot/wp-admin/includes/class-wp-list-table.php:242 |
| WP_List_Table | __unset | lab-wp-zendmm/webroot/wp-admin/includes/class-wp-list-table.php:264 |
| WP_List_Table | __call | lab-wp-zendmm/webroot/wp-admin/includes/class-wp-list-table.php:287 |
| WP_UAF_Gadget | __destruct | lab-wp-zendmm/webroot/wp-content/mu-plugins/uaf-harness.php:25 |
| WP_UAF_Gadget | __destruct | lab-wp-zendmm/webroot/wp-content/mu-plugins/uaf-harness.php:25 |
| WP_VD_Gadget | __destruct | lab-wp-zendmm/webroot/wp-content/mu-plugins/vd-harness.php:36 |
| WP_VD_Gadget | __destruct | lab-wp-zendmm/webroot/wp-content/mu-plugins/vd-harness.php:36 |
| PHPMailer\PHPMailer\PHPMailer | __destruct | lab-wp-zendmm/webroot/wp-includes/PHPMailer/PHPMailer.php:857 |
| WpOrg\Requests\Cookie | __toString | lab-wp-zendmm/webroot/wp-includes/Requests/src/Cookie.php:127 |
| WpOrg\Requests\Hooks | __wakeup | lab-wp-zendmm/webroot/wp-includes/Requests/src/Hooks.php:100 |
| WpOrg\Requests\Iri | __toString | lab-wp-zendmm/webroot/wp-includes/Requests/src/Iri.php:153 |
| WpOrg\Requests\Iri | __set | lab-wp-zendmm/webroot/wp-includes/Requests/src/Iri.php:163 |
| WpOrg\Requests\Iri | __set | lab-wp-zendmm/webroot/wp-includes/Requests/src/Iri.php:163 |

## Stream / session markers

None in this tree.

## Semgrep (candidate files only)

| rule | file | line | message |
|---|---|---|---|
| php-magic-terminal | lab-wp-zendmm/webroot/api/endpoint.php | 22 | magic method reaches a terminal command sink |
| php-magic-reentry | lab-wp-zendmm/webroot/wp-content/mu-plugins/uaf-harness.php | 33 | magic method re-enters deserialization |
| php-magic-reentry | lab-wp-zendmm/webroot/wp-content/mu-plugins/vd-harness.php | 46 | magic method re-enters deserialization |

## Tools

- **ast-grep**: 2566 matches
- **ctags**: ok
- **semgrep**: 3 findings
- **rg**: ok

## Reproduce

```sh
scripts/gadget_sweep.sh lab-wp-zendmm/webroot --label wordpress
```
