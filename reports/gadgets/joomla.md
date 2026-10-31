# Gadget sweep: `joomla`

Root `lab-joomla/webroot` — 6077 PHP files, 508 magic methods, 792 candidates, 0 re-entry.

Candidate generation only. A hit means *read this next*, not *exploitable*; dynamic reachability and the lab decide that.

## Ranked candidates

| score | kind | class | method | sinks | where |
|---|---|---|---|---|---|
| 90 | terminal | FileLogger | __destruct | file, terminal | lab-joomla/webroot/api/endpoint.php:16 |
| 80 | dispatch | DebugBar\Bridge\Twig\TraceableTwigEnvironment | __call | dispatch | lab-joomla/webroot/libraries/vendor/php-debugbar/php-debugbar/src/DebugBar/Bridge/Twig/TraceableTwigEnvironment.php:48 |
| 80 | dispatch | DebugBar\Bridge\Twig\TraceableTwigTemplate | __call | dispatch | lab-joomla/webroot/libraries/vendor/php-debugbar/php-debugbar/src/DebugBar/Bridge/Twig/TraceableTwigTemplate.php:35 |
| 80 | dispatch | DebugBar\DataCollector\PDO\TraceablePDO | __call | dispatch | lab-joomla/webroot/libraries/vendor/php-debugbar/php-debugbar/src/DebugBar/DataCollector/PDO/TraceablePDO.php:338 |
| 80 | dispatch | bcmath_compat\BCMath | __callStatic | autoload, dispatch | lab-joomla/webroot/libraries/vendor/phpseclib/bcmath_compat/src/BCMath.php:352 |
| 60 | file | ZIPExtraction | __wakeup | file | lab-joomla/webroot/administrator/components/com_joomlaupdate/extract.php:492 |
| 45 | terminal | Joomla\CMS\Application\DaemonApplication | changeIdentity | terminal | lab-joomla/webroot/libraries/src/Application/DaemonApplication.php:433 |
| 45 | terminal | Joomla\CMS\Application\DaemonApplication | shutdown | file, terminal | lab-joomla/webroot/libraries/src/Application/DaemonApplication.php:692 |
| 45 | dispatch | Composer\Autoload\ClassLoader | getPrefixes | dispatch | lab-joomla/webroot/libraries/vendor/composer/ClassLoader.php:115 |
| 45 | dispatch | ComposerAutoloaderInitac882cb614894c583b265528f6e9f688 | getLoader | autoload, dispatch, file | lab-joomla/webroot/libraries/vendor/composer/autoload_real.php:19 |
| 45 | dispatch | ParagonIE_Sodium_Compat | bin2hex | dispatch | lab-joomla/webroot/libraries/vendor/paragonie/sodium_compat/src/Compat.php:279 |
| 45 | dispatch | ParagonIE_Sodium_Compat | compare | dispatch | lab-joomla/webroot/libraries/vendor/paragonie/sodium_compat/src/Compat.php:308 |
| 45 | dispatch | ParagonIE_Sodium_Compat | crypto_aead_aes256gcm_is_available | autoload, dispatch | lab-joomla/webroot/libraries/vendor/paragonie/sodium_compat/src/Compat.php:553 |
| 45 | dispatch | ParagonIE_Sodium_Compat | crypto_aead_chacha20poly1305_decrypt | dispatch | lab-joomla/webroot/libraries/vendor/paragonie/sodium_compat/src/Compat.php:738 |
| 45 | dispatch | ParagonIE_Sodium_Compat | crypto_aead_chacha20poly1305_encrypt | dispatch | lab-joomla/webroot/libraries/vendor/paragonie/sodium_compat/src/Compat.php:819 |
| 45 | dispatch | ParagonIE_Sodium_Compat | crypto_aead_chacha20poly1305_ietf_decrypt | dispatch | lab-joomla/webroot/libraries/vendor/paragonie/sodium_compat/src/Compat.php:895 |
| 45 | dispatch | ParagonIE_Sodium_Compat | crypto_aead_chacha20poly1305_ietf_encrypt | dispatch | lab-joomla/webroot/libraries/vendor/paragonie/sodium_compat/src/Compat.php:989 |
| 45 | dispatch | ParagonIE_Sodium_Compat | crypto_auth | dispatch | lab-joomla/webroot/libraries/vendor/paragonie/sodium_compat/src/Compat.php:1238 |
| 45 | dispatch | ParagonIE_Sodium_Compat | crypto_auth_verify | dispatch | lab-joomla/webroot/libraries/vendor/paragonie/sodium_compat/src/Compat.php:1286 |
| 45 | dispatch | ParagonIE_Sodium_Compat | crypto_box | dispatch | lab-joomla/webroot/libraries/vendor/paragonie/sodium_compat/src/Compat.php:1334 |
| 45 | dispatch | ParagonIE_Sodium_Compat | crypto_box_seal | dispatch | lab-joomla/webroot/libraries/vendor/paragonie/sodium_compat/src/Compat.php:1382 |
| 45 | dispatch | ParagonIE_Sodium_Compat | crypto_box_seal_open | dispatch | lab-joomla/webroot/libraries/vendor/paragonie/sodium_compat/src/Compat.php:1423 |
| 45 | dispatch | ParagonIE_Sodium_Compat | crypto_box_keypair | dispatch | lab-joomla/webroot/libraries/vendor/paragonie/sodium_compat/src/Compat.php:1464 |
| 45 | dispatch | ParagonIE_Sodium_Compat | crypto_box_keypair_from_secretkey_and_publickey | dispatch | lab-joomla/webroot/libraries/vendor/paragonie/sodium_compat/src/Compat.php:1489 |
| 45 | dispatch | ParagonIE_Sodium_Compat | crypto_box_open | dispatch | lab-joomla/webroot/libraries/vendor/paragonie/sodium_compat/src/Compat.php:1531 |

## Re-entry candidates (magic -> unserialize)

None in this tree.

## Magic method inventory

| magic method | count |
|---|---|
| __get | 122 |
| __toString | 122 |
| __set | 97 |
| __destruct | 35 |
| __sleep | 24 |
| __wakeup | 18 |
| __call | 17 |
| __clone | 14 |
| __isset | 12 |
| __serialize | 12 |
| __unserialize | 11 |
| __invoke | 9 |
| __debugInfo | 8 |
| __callStatic | 4 |
| __unset | 3 |

| class | method | where |
|---|---|---|
| Joomla\Component\Categories\Administrator\Field\CategoryeditField | __get | lab-joomla/webroot/administrator/components/com_categories/src/Field/CategoryeditField.php:98 |
| Joomla\Component\Categories\Administrator\Field\CategoryeditField | __get | lab-joomla/webroot/administrator/components/com_categories/src/Field/CategoryeditField.php:98 |
| Joomla\Component\Categories\Administrator\Field\CategoryeditField | __set | lab-joomla/webroot/administrator/components/com_categories/src/Field/CategoryeditField.php:120 |
| Joomla\Component\Categories\Administrator\Field\CategoryeditField | __set | lab-joomla/webroot/administrator/components/com_categories/src/Field/CategoryeditField.php:120 |
| Joomla\Component\Finder\Administrator\Indexer\Result | __set | lab-joomla/webroot/administrator/components/com_finder/src/Indexer/Result.php:214 |
| Joomla\Component\Finder\Administrator\Indexer\Result | __get | lab-joomla/webroot/administrator/components/com_finder/src/Indexer/Result.php:228 |
| Joomla\Component\Finder\Administrator\Indexer\Result | __isset | lab-joomla/webroot/administrator/components/com_finder/src/Indexer/Result.php:242 |
| Joomla\Component\Finder\Administrator\Indexer\Result | __unset | lab-joomla/webroot/administrator/components/com_finder/src/Indexer/Result.php:256 |
| Joomla\Component\Finder\Administrator\Indexer\Result | __serialize | lab-joomla/webroot/administrator/components/com_finder/src/Indexer/Result.php:498 |
| Joomla\Component\Finder\Administrator\Indexer\Result | __unserialize | lab-joomla/webroot/administrator/components/com_finder/src/Indexer/Result.php:545 |
| ZIPExtraction | __wakeup | lab-joomla/webroot/administrator/components/com_joomlaupdate/extract.php:492 |
| ZIPExtraction | __wakeup | lab-joomla/webroot/administrator/components/com_joomlaupdate/extract.php:492 |
| Joomla\Component\Menus\Administrator\Field\MenuItemByTypeField | __get | lab-joomla/webroot/administrator/components/com_menus/src/Field/MenuItemByTypeField.php:87 |
| Joomla\Component\Menus\Administrator\Field\MenuItemByTypeField | __get | lab-joomla/webroot/administrator/components/com_menus/src/Field/MenuItemByTypeField.php:87 |
| Joomla\Component\Menus\Administrator\Field\MenuItemByTypeField | __set | lab-joomla/webroot/administrator/components/com_menus/src/Field/MenuItemByTypeField.php:111 |
| Joomla\Component\Menus\Administrator\Field\MenuItemByTypeField | __set | lab-joomla/webroot/administrator/components/com_menus/src/Field/MenuItemByTypeField.php:111 |
| Joomla\Component\Menus\Administrator\Field\Modal\MenuField | __get | lab-joomla/webroot/administrator/components/com_menus/src/Field/Modal/MenuField.php:51 |
| Joomla\Component\Menus\Administrator\Field\Modal\MenuField | __get | lab-joomla/webroot/administrator/components/com_menus/src/Field/Modal/MenuField.php:51 |
| Joomla\Component\Menus\Administrator\Field\Modal\MenuField | __get | lab-joomla/webroot/administrator/components/com_menus/src/Field/Modal/MenuField.php:51 |
| Joomla\Component\Menus\Administrator\Field\Modal\MenuField | __set | lab-joomla/webroot/administrator/components/com_menus/src/Field/Modal/MenuField.php:94 |

## Stream / session markers

| file | line | text |
|---|---|---|
| libraries/src/Session/SessionFactory.php | 89 | ini_set('session.save_handler', 'memcached'); |
| api/handler_probe.php | 2 | echo "handler=" . ini_get("session.serialize_handler") . " |
| sysinfo.php | 4 | echo "upload_progress " . ini_get('session.upload_progress.enabled') . "\n"; |
| libraries/vendor/joomla/session/src/Handler/WincacheHandler.php | 29 | ini_set('session.save_handler', 'wincache'); |
| libraries/vendor/joomla/session/src/Handler/FilesystemHandler.php | 42 | ini_set('session.save_handler', 'files'); |
| libraries/vendor/joomla/session/src/Handler/FilesystemHandler.php | 68 | ini_set('session.save_handler', 'files'); |
| libraries/vendor/typo3/phar-stream-wrapper/src/Helper.php | 42 | * For e.g. "phar:///home/user/bundle.phar/content.txt" that would result |
| libraries/vendor/typo3/phar-stream-wrapper/src/Helper.php | 64 | return stripos($path, 'phar://') === 0; |
| libraries/vendor/typo3/phar-stream-wrapper/src/Helper.php | 77 | * Normalizes a path, removes phar:// prefix, fixes Windows directory |
| libraries/vendor/composer/ca-bundle/src/CaBundle.php | 127 | // cURL does not understand 'phar://' paths |
| libraries/vendor/composer/ca-bundle/src/CaBundle.php | 129 | if (0 === strpos($caBundleFile, 'phar://')) { |

## Semgrep (candidate files only)

| rule | file | line | message |
|---|---|---|---|
| php-magic-terminal | lab-joomla/webroot/api/endpoint.php | 22 | magic method reaches a terminal command sink |

## Tools

- **ast-grep**: 1871 matches
- **ctags**: ok
- **semgrep**: 1 findings
- **rg**: ok

## Reproduce

```sh
scripts/gadget_sweep.sh lab-joomla/webroot --label joomla
```
