# Gadget sweep: `drupal`

Root `lab-drupal` — 7923 PHP files, 604 magic methods, 900 candidates, 0 re-entry.

Candidate generation only. A hit means *read this next*, not *exploitable*; dynamic reachability and the lab decide that.

## Ranked candidates

| score | kind | class | method | sinks | where |
|---|---|---|---|---|---|
| 80 | dispatch | Drupal\Component\Annotation\Plugin\Discovery\AnnotationBridgeDecorator | __call | dispatch | lab-drupal/core/lib/Drupal/Component/Annotation/Plugin/Discovery/AnnotationBridgeDecorator.php:71 |
| 80 | dispatch | Drupal\Component\Datetime\DateTimePlus | __call | autoload, dispatch | lab-drupal/core/lib/Drupal/Component/Datetime/DateTimePlus.php:298 |
| 80 | dispatch | Drupal\Component\Datetime\DateTimePlus | __callStatic | autoload, dispatch | lab-drupal/core/lib/Drupal/Component/Datetime/DateTimePlus.php:341 |
| 80 | dispatch | Drupal\Component\Plugin\Discovery\DerivativeDiscoveryDecorator | __call | dispatch | lab-drupal/core/lib/Drupal/Component/Plugin/Discovery/DerivativeDiscoveryDecorator.php:266 |
| 80 | dispatch | Drupal\Component\Plugin\Discovery\StaticDiscoveryDecorator | __call | dispatch | lab-drupal/core/lib/Drupal/Component/Plugin/Discovery/StaticDiscoveryDecorator.php:63 |
| 80 | dispatch | Drupal\Core\Database\Query\SelectExtender | __call | dispatch | lab-drupal/core/lib/Drupal/Core/Database/Query/SelectExtender.php:519 |
| 80 | dispatch | Drupal\Core\Plugin\Discovery\InfoHookDecorator | __call | dispatch | lab-drupal/core/lib/Drupal/Core/Plugin/Discovery/InfoHookDecorator.php:59 |
| 80 | dispatch | Drupal\Core\Plugin\Discovery\YamlDiscoveryDecorator | __call | dispatch | lab-drupal/core/lib/Drupal/Core/Plugin/Discovery/YamlDiscoveryDecorator.php:49 |
| 80 | dispatch | Drupal\Core\Routing\AccessAwareRouter | __call | dispatch | lab-drupal/core/lib/Drupal/Core/Routing/AccessAwareRouter.php:63 |
| 80 | dispatch | Drupal\migrate\Plugin\Discovery\ProviderFilterDecorator | __call | dispatch | lab-drupal/core/modules/migrate/src/Plugin/Discovery/ProviderFilterDecorator.php:99 |
| 80 | dispatch | Drupal\migrate\Plugin\NoSourcePluginDecorator | __call | dispatch | lab-drupal/core/modules/migrate/src/Plugin/NoSourcePluginDecorator.php:54 |
| 80 | dispatch | Drupal\views_ui\ViewUI | __call | dispatch | lab-drupal/core/modules/views_ui/src/ViewUI.php:927 |
| 80 | dispatch | PEAR | __call | dispatch | lab-drupal/vendor/pear/pear-core-minimal/src/PEAR.php:216 |
| 80 | dispatch | PEAR | __callStatic | dispatch | lab-drupal/vendor/pear/pear-core-minimal/src/PEAR.php:233 |
| 80 | dispatch | PhpTuf\ComposerStager\Internal\Process\Service\OutputCallbackAdapter | __invoke | dispatch | lab-drupal/vendor/php-tuf/composer-stager/src/Internal/Process/Service/OutputCallbackAdapter.php:20 |
| 60 | file | Drupal\Core\Command\CacheRebuildCommand | __invoke | file | lab-drupal/core/lib/Drupal/Core/Command/CacheRebuildCommand.php:39 |
| 60 | file | Drupal\package_manager\FileProcessOutputCallback | __invoke | file | lab-drupal/core/modules/package_manager/src/FileProcessOutputCallback.php:68 |
| 60 | file | Drupal\sqlite\Driver\Database\sqlite\Connection | __destruct | file | lab-drupal/core/modules/sqlite/src/Driver/Database/sqlite/Connection.php:204 |
| 60 | file | VdHold | __destruct | file | lab-drupal/vd.php:35 |
| 60 | file | VdDtorProbe | __destruct | file | lab-drupal/vd.php:47 |
| 60 | file | VdHoldDisc_______________________________________ | __destruct | file | lab-drupal/vd.php:59 |
| 60 | file | VdDtorProbe | __destruct | file | lab-drupal/vd_session_cli.php:17 |
| 60 | file | Archive_Tar | __destruct | file | lab-drupal/vendor/pear/archive_tar/Archive/Tar.php:235 |
| 45 | dispatch | Drupal\Component\ClassFinder\ClassFinder | findFile | autoload, dispatch | lab-drupal/core/lib/Drupal/Component/ClassFinder/ClassFinder.php:13 |
| 45 | dispatch | Drupal\Component\DependencyInjection\Container | createService | autoload, dispatch, file | lab-drupal/core/lib/Drupal/Component/DependencyInjection/Container.php:230 |

## Re-entry candidates (magic -> unserialize)

None in this tree.

## Magic method inventory

| magic method | count |
|---|---|
| __toString | 118 |
| __serialize | 67 |
| __unserialize | 60 |
| __sleep | 54 |
| __destruct | 53 |
| __clone | 50 |
| __get | 40 |
| __invoke | 40 |
| __call | 36 |
| __set | 21 |
| __wakeup | 19 |
| __isset | 19 |
| __unset | 14 |
| __callStatic | 7 |
| __debugInfo | 6 |

| class | method | where |
|---|---|---|
| GuzzleHttp\Cookie\FileCookieJar | __destruct | lab-drupal/core/includes/guzzle_file_cookie_jar_shim.php:69 |
| GuzzleHttp\Cookie\FileCookieJar | __wakeup | lab-drupal/core/includes/guzzle_file_cookie_jar_shim.php:79 |
| Drupal\Component\Annotation\Doctrine\Annotation | __get | lab-drupal/core/lib/Drupal/Component/Annotation/Doctrine/Annotation.php:57 |
| Drupal\Component\Annotation\Doctrine\Annotation | __set | lab-drupal/core/lib/Drupal/Component/Annotation/Doctrine/Annotation.php:71 |
| Drupal\Component\Annotation\Doctrine\StaticReflectionClass | __toString | lab-drupal/core/lib/Drupal/Component/Annotation/Doctrine/StaticReflectionClass.php:446 |
| Drupal\Component\Annotation\Plugin\Discovery\AnnotationBridgeDecorator | __call | lab-drupal/core/lib/Drupal/Component/Annotation/Plugin/Discovery/AnnotationBridgeDecorator.php:71 |
| Drupal\Component\Annotation\Plugin\Discovery\AnnotationBridgeDecorator | __call | lab-drupal/core/lib/Drupal/Component/Annotation/Plugin/Discovery/AnnotationBridgeDecorator.php:71 |
| Drupal\Component\Datetime\DateTimePlus | __call | lab-drupal/core/lib/Drupal/Component/Datetime/DateTimePlus.php:298 |
| Drupal\Component\Datetime\DateTimePlus | __call | lab-drupal/core/lib/Drupal/Component/Datetime/DateTimePlus.php:298 |
| Drupal\Component\Datetime\DateTimePlus | __call | lab-drupal/core/lib/Drupal/Component/Datetime/DateTimePlus.php:298 |
| Drupal\Component\Datetime\DateTimePlus | __callStatic | lab-drupal/core/lib/Drupal/Component/Datetime/DateTimePlus.php:341 |
| Drupal\Component\Datetime\DateTimePlus | __callStatic | lab-drupal/core/lib/Drupal/Component/Datetime/DateTimePlus.php:341 |
| Drupal\Component\Datetime\DateTimePlus | __callStatic | lab-drupal/core/lib/Drupal/Component/Datetime/DateTimePlus.php:341 |
| Drupal\Component\Datetime\DateTimePlus | __clone | lab-drupal/core/lib/Drupal/Component/Datetime/DateTimePlus.php:353 |
| Drupal\Component\Datetime\DateTimePlus | __toString | lab-drupal/core/lib/Drupal/Component/Datetime/DateTimePlus.php:685 |
| Drupal\Component\DependencyInjection\Container | __clone | lab-drupal/core/lib/Drupal/Component/DependencyInjection/Container.php:549 |
| Drupal\Component\Gettext\PoHeader | __toString | lab-drupal/core/lib/Drupal/Component/Gettext/PoHeader.php:152 |
| Drupal\Component\Gettext\PoItem | __toString | lab-drupal/core/lib/Drupal/Component/Gettext/PoItem.php:217 |
| Drupal\Component\Plugin\Discovery\AttributeBridgeDecorator | __call | lab-drupal/core/lib/Drupal/Component/Plugin/Discovery/AttributeBridgeDecorator.php:65 |
| Drupal\Component\Plugin\Discovery\DerivativeDiscoveryDecorator | __call | lab-drupal/core/lib/Drupal/Component/Plugin/Discovery/DerivativeDiscoveryDecorator.php:266 |

## Stream / session markers

| file | line | text |
|---|---|---|
| vd_session_cli.php | 28 | @ini_set('session.save_handler', 'files'); |
| vd_session_cli.php | 33 | @ini_set('session.serialize_handler', 'php'); |
| vd.php | 73 | " handler=" . ini_get('session.serialize_handler')); |
| vd.php | 96 | @ini_set('session.serialize_handler', 'php'); |
| vd.php | 99 | " sid=" . session_id() . " handler=" . ini_get('session.serialize_handler')); |
| vendor/symfony/dependency-injection/Loader/XmlFileLoader.php | 762 | if (0 === stripos($location, 'phar://')) { |
| vendor/symfony/dependency-injection/Loader/XmlFileLoader.php | 771 | $location = 'phar:///'.$drive.implode('/', array_map('rawurlencode', $parts)); |
| vendor/symfony/http-foundation/Session/Storage/Proxy/AbstractProxy.php | 24 | * Gets the session.save_handler name. |
| vendor/symfony/http-foundation/Session/Storage/Proxy/SessionHandlerProxy.php | 25 | $this->saveHandlerName = $this->wrapper || ($handler instanceof StrictSessionHandler && $handler->isWrapper()) ? \ini_get('session.save_handler') : 'user'; |
| vendor/symfony/http-foundation/Session/Storage/NativeSessionStorage.php | 350 | * session.save_handler and session.save_path e.g. |
| vendor/symfony/http-foundation/Session/Storage/NativeSessionStorage.php | 352 | *     ini_set('session.save_handler', 'files'); |
| vendor/symfony/http-foundation/Session/Storage/NativeSessionStorage.php | 355 | * or pass in a \SessionHandler instance which configures session.save_handler in the |
| vendor/symfony/http-foundation/Session/Storage/Handler/NativeFileSessionHandler.php | 51 | if ('files' !== \ini_get('session.save_handler')) { |
| vendor/symfony/http-foundation/Session/Storage/Handler/NativeFileSessionHandler.php | 52 | ini_set('session.save_handler', 'files'); |
| vendor/symfony/filesystem/Path.php | 686 | // For first part we keep slashes, like '/top', 'C:\' or 'phar://' |
| vendor/symfony/filesystem/Path.php | 697 | // If first part included a scheme like 'phar://' we allow \current part to start with '/', otherwise trim |

## Semgrep (candidate files only)

| rule | file | line | message |
|---|---|---|---|
| php-session-handler-switch | lab-drupal/vd.php | 96 | session serialization handler is switched at runtime |
| php-session-handler-switch | lab-drupal/vd_session_cli.php | 33 | session serialization handler is switched at runtime |

## Tools

- **ast-grep**: 1966 matches
- **ctags**: ok
- **semgrep**: 2 findings
- **rg**: ok

## Reproduce

```sh
scripts/gadget_sweep.sh lab-drupal --label drupal
```
