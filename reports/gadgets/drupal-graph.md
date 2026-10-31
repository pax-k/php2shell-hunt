# Cross-class gadget graph: `drupal`

Root `lab-drupal` — 7494 classes, 36321 methods, 199 entries, 21283 visited nodes, 193 paths.

Typed property/interface expansion via PHP-Parser facts. This finds chains the same-method sweep cannot; it still does not prove reachability or attacker control.

## Top paths

| score | sink | depth | chain | sink at |
|---|---|---|---|---|
| 97 | reentry | 1 | `PrototypeConfigurator::__destruct -> PhpFileLoader::registerClasses -> unserialize()` | vendor/symfony/dependency-injection/Loader/FileLoader.php:145 |
| 97 | reentry | 1 | `PrototypeConfigurator::__destruct -> ProtectedPhpFileLoader::registerClasses -> unserialize()` | vendor/symfony/dependency-injection/Loader/FileLoader.php:145 |
| 94 | reentry | 2 | `ServiceConfigurator::__destruct -> PrototypeConfigurator::__destruct -> PhpFileLoader::registerClasses -> unserialize()` | vendor/symfony/dependency-injection/Loader/FileLoader.php:145 |
| 94 | reentry | 2 | `ServiceConfigurator::__destruct -> PrototypeConfigurator::__destruct -> ProtectedPhpFileLoader::registerClasses -> unserialize()` | vendor/symfony/dependency-injection/Loader/FileLoader.php:145 |
| 91 | reentry | 3 | `YamlCacheCollectorDiscovery::__destruct -> MenuActiveTrail::destruct -> MenuActiveTrail::lazyLoadItself -> Container::get -> unserialize()` | core/lib/Drupal/Component/DependencyInjection/Container.php:166 |
| 91 | reentry | 3 | `YamlCacheCollectorDiscovery::__destruct -> MenuActiveTrail::destruct -> MenuActiveTrail::lazyLoadItself -> PhpArrayContainer::get -> unserialize()` | core/lib/Drupal/Component/DependencyInjection/Container.php:166 |
| 91 | reentry | 3 | `YamlCacheCollectorDiscovery::__destruct -> MenuActiveTrail::destruct -> MenuActiveTrail::lazyLoadItself -> Container::get -> unserialize()` | core/lib/Drupal/Component/DependencyInjection/Container.php:166 |
| 91 | reentry | 3 | `FromCallableConfigurator::__destruct -> ServiceConfigurator::__destruct -> PrototypeConfigurator::__destruct -> PhpFileLoader::registerClasses -> unserialize()` | vendor/symfony/dependency-injection/Loader/FileLoader.php:145 |
| 91 | reentry | 3 | `FromCallableConfigurator::__destruct -> ServiceConfigurator::__destruct -> PrototypeConfigurator::__destruct -> ProtectedPhpFileLoader::registerClasses -> unserialize()` | vendor/symfony/dependency-injection/Loader/FileLoader.php:145 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> LibraryDiscoveryCollector::destruct -> LibraryDiscoveryCollector::updateCache -> MemoryBackend::get -> MemoryBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> LibraryDiscoveryCollector::destruct -> LibraryDiscoveryCollector::updateCache -> MemoryBackend::get -> MemoryCounterBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> MenuActiveTrail::destruct -> MenuActiveTrail::updateCache -> MemoryBackend::get -> MemoryBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> MenuActiveTrail::destruct -> MenuActiveTrail::updateCache -> MemoryBackend::get -> MemoryCounterBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> State::destruct -> State::updateCache -> MemoryBackend::get -> MemoryBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> State::destruct -> State::updateCache -> MemoryBackend::get -> MemoryCounterBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> IconCollector::destruct -> IconCollector::updateCache -> MemoryBackend::get -> MemoryBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> IconCollector::destruct -> IconCollector::updateCache -> MemoryBackend::get -> MemoryCounterBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> BlockContentUuidLookup::destruct -> BlockContentUuidLookup::updateCache -> MemoryBackend::get -> MemoryBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> BlockContentUuidLookup::destruct -> BlockContentUuidLookup::updateCache -> MemoryBackend::get -> MemoryCounterBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> LocaleLookup::destruct -> LocaleLookup::updateCache -> MemoryBackend::get -> MemoryBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> LocaleLookup::destruct -> LocaleLookup::updateCache -> MemoryBackend::get -> MemoryCounterBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> AliasPrefixList::destruct -> AliasPrefixList::updateCache -> MemoryBackend::get -> MemoryBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> AliasPrefixList::destruct -> AliasPrefixList::updateCache -> MemoryBackend::get -> MemoryCounterBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> AliasPrefixList::destruct -> AliasWhitelist::updateCache -> MemoryBackend::get -> MemoryBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> AliasPrefixList::destruct -> AliasWhitelist::updateCache -> MemoryBackend::get -> MemoryCounterBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> AliasWhitelist::destruct -> AliasWhitelist::updateCache -> MemoryBackend::get -> MemoryBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 88 | reentry | 4 | `YamlCacheCollectorDiscovery::__destruct -> AliasWhitelist::destruct -> AliasWhitelist::updateCache -> MemoryBackend::get -> MemoryCounterBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 85 | reentry | 5 | `StorageComparer::__wakeup -> ChainedFastBackend::deleteAll -> ChainedFastBackend::markAsOutdated -> ChainedFastBackend::getLastWriteTimestamp -> MemoryBackend::get -> MemoryBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 85 | reentry | 5 | `StorageComparer::__wakeup -> ChainedFastBackend::deleteAll -> ChainedFastBackend::markAsOutdated -> ChainedFastBackend::getLastWriteTimestamp -> MemoryBackend::get -> MemoryCounterBackend::prepareItem -> unserialize()` | core/lib/Drupal/Core/Cache/MemoryBackend.php:99 |
| 84 | terminal | 2 | `PhpProcess::__destruct -> PhpProcess::stop -> PhpProcess::doSignal -> exec()` | vendor/symfony/process/Process.php:1551 |

## Reproduce

```sh
scripts/gadget_graph.sh lab-drupal --label drupal
```
