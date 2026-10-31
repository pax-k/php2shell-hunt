# Cross-class gadget graph: `roundcube-graph`

Root `lab-roundcube/roundcubemail-1.6.11` — 583 classes, 4749 methods, 22 entries, 154 visited nodes, 58 paths.

Typed property/interface expansion via PHP-Parser facts. This finds chains the same-method sweep cannot; it still does not prove reachability or attacker control.

## Top paths

| score | sink | depth | chain | sink at |
|---|---|---|---|---|
| 100 | reentry | 0 | `CachePurge::__destruct -> unserialize()` | plugins/vd115560/vd115560.php:108 |
| 97 | reentry | 1 | `EnumMap::__unserialize -> EnumMap::unserialize -> unserialize()` | vendor/dasprid/enum/src/EnumMap.php:294 |
| 90 | terminal | 0 | `VdSimple::__destruct -> exec()` | plugins/vd115560/vd115560.php:54 |
| 87 | terminal | 1 | `Crypt_GPG_Engine::__destruct -> Crypt_GPG_Engine::_closeIdleAgents -> proc_open()` | vendor/pear/crypt_gpg/Crypt/GPG/Engine.php:1840 |
| 84 | terminal | 2 | `Crypt_GPG_Engine::__destruct -> Crypt_GPG_Engine::_closeSubprocess -> Crypt_GPG_ProcessControl::terminate -> exec()` | vendor/pear/crypt_gpg/Crypt/GPG/ProcessControl.php:123 |
| 84 | terminal | 2 | `Crypt_GPG_Engine::__destruct -> Crypt_GPG_Engine::_closeSubprocess -> Crypt_GPG_ProcessControl::terminate -> exec()` | vendor/pear/crypt_gpg/Crypt/GPG/ProcessControl.php:125 |
| 84 | terminal | 2 | `Crypt_GPG_Engine::__destruct -> Crypt_GPG_Engine::_closeSubprocess -> Crypt_GPG_ProcessControl::isRunning -> exec()` | vendor/pear/crypt_gpg/Crypt/GPG/ProcessControl.php:94 |
| 84 | terminal | 2 | `Crypt_GPG_Engine::__destruct -> Crypt_GPG_Engine::_closeSubprocess -> Crypt_GPG_ProcessControl::isRunning -> exec()` | vendor/pear/crypt_gpg/Crypt/GPG/ProcessControl.php:98 |
| 64 | dispatch | 2 | `Crypt_GPG_Engine::__destruct -> Crypt_GPG_Engine::_closeSubprocess -> Crypt_GPG_Engine::_debug -> call_user_func()` | vendor/pear/crypt_gpg/Crypt/GPG/Engine.php:1965 |
| 61 | dispatch | 3 | `Crypt_GPG_Engine::__destruct -> Crypt_GPG_Engine::_closeSubprocess -> Crypt_GPG_Engine::_closeAgentLaunchProcess -> Crypt_GPG_Engine::_debug -> call_user_func()` | vendor/pear/crypt_gpg/Crypt/GPG/Engine.php:1965 |
| 61 | dispatch | 3 | `rcube_sieve::__destruct -> Net_Sieve::disconnect -> Net_Sieve::_cmdLogout -> PEAR::__call -> call_user_func_array()` | vendor/pear/pear-core-minimal/src/PEAR.php:223 |
| 58 | dispatch | 4 | `rcube_sieve::__destruct -> Net_Sieve::disconnect -> Net_Sieve::_cmdLogout -> Net_Sieve::_doCmd -> PEAR::__call -> call_user_func_array()` | vendor/pear/pear-core-minimal/src/PEAR.php:223 |
| 58 | dispatch | 4 | `rcube_sieve::__destruct -> Net_Sieve::disconnect -> Net_Sieve::_cmdLogout -> Net_Socket::disconnect -> Net_Socket::__call -> call_user_func_array()` | vendor/pear/pear-core-minimal/src/PEAR.php:223 |
| 55 | dispatch | 5 | `rcube_sieve::__destruct -> Net_Sieve::disconnect -> Net_Sieve::_cmdLogout -> Net_Sieve::_doCmd -> Net_Sieve::_sendCmd -> PEAR::__call -> call_user_func_array()` | vendor/pear/pear-core-minimal/src/PEAR.php:223 |
| 55 | dispatch | 5 | `rcube_sieve::__destruct -> Net_Sieve::disconnect -> Net_Sieve::_cmdLogout -> Net_Sieve::_doCmd -> Net_Sieve::_sendCmd -> Net_Sieve::_debug -> call_user_func_array()` | vendor/pear/net_sieve/Sieve.php:1540 |
| 55 | dispatch | 5 | `rcube_sieve::__destruct -> Net_Sieve::disconnect -> Net_Sieve::_cmdLogout -> Net_Sieve::_doCmd -> Net_Sieve::_recvLn -> PEAR::__call -> call_user_func_array()` | vendor/pear/pear-core-minimal/src/PEAR.php:223 |
| 55 | dispatch | 5 | `rcube_sieve::__destruct -> Net_Sieve::disconnect -> Net_Sieve::_cmdLogout -> Net_Sieve::_doCmd -> Net_Sieve::_recvLn -> Net_Sieve::_debug -> call_user_func_array()` | vendor/pear/net_sieve/Sieve.php:1540 |
| 55 | dispatch | 5 | `rcube_sieve::__destruct -> Net_Sieve::disconnect -> Net_Sieve::_cmdLogout -> Net_Sieve::_doCmd -> Net_Sieve::_recvBytes -> Net_Sieve::_debug -> call_user_func_array()` | vendor/pear/net_sieve/Sieve.php:1540 |
| 52 | dispatch | 6 | `rcube_sieve::__destruct -> Net_Sieve::disconnect -> Net_Sieve::_cmdLogout -> Net_Sieve::_doCmd -> Net_Sieve::_sendCmd -> Net_Socket::getStatus -> Net_Socket::__call -> call_user_func_array()` | vendor/pear/pear-core-minimal/src/PEAR.php:223 |
| 52 | dispatch | 6 | `rcube_sieve::__destruct -> Net_Sieve::disconnect -> Net_Sieve::_cmdLogout -> Net_Sieve::_doCmd -> Net_Sieve::_recvLn -> Net_Socket::gets -> Net_Socket::__call -> call_user_func_array()` | vendor/pear/pear-core-minimal/src/PEAR.php:223 |
| 52 | dispatch | 6 | `rcube_sieve::__destruct -> Net_Sieve::disconnect -> Net_Sieve::_cmdLogout -> Net_Sieve::_doCmd -> Net_Sieve::_recvBytes -> Net_Socket::read -> Net_Socket::__call -> call_user_func_array()` | vendor/pear/pear-core-minimal/src/PEAR.php:223 |
| 52 | dispatch | 6 | `rcube_sieve::__destruct -> Net_Sieve::disconnect -> Net_Sieve::_cmdLogout -> Net_Sieve::_doCmd -> Net_Sieve::_handleConnectAndLogin -> Net_Sieve::connect -> PEAR::__call -> call_user_func_array()` | vendor/pear/pear-core-minimal/src/PEAR.php:223 |
| 52 | dispatch | 6 | `rcube_sieve::__destruct -> Net_Sieve::disconnect -> Net_Sieve::_cmdLogout -> Net_Sieve::_doCmd -> Net_Sieve::_handleConnectAndLogin -> Net_Sieve::login -> PEAR::__call -> call_user_func_array()` | vendor/pear/pear-core-minimal/src/PEAR.php:223 |
| 50 | file | 0 | `CachePurge::__destruct -> file_put_contents()` | plugins/vd115560/vd115560.php:84 |
| 50 | file | 0 | `CachePurge::__destruct -> file_put_contents()` | plugins/vd115560/vd115560.php:90 |
| 50 | file | 0 | `CachePurge::__destruct -> file_put_contents()` | plugins/vd115560/vd115560.php:97 |
| 50 | file | 0 | `rcmail_attachment_handler::__destruct -> unlink()` | program/include/rcmail_attachment_handler.php:126 |
| 50 | file | 0 | `rcmail_sendmail::__destruct -> unlink()` | program/include/rcmail_sendmail.php:85 |
| 49 | dispatch | 7 | `rcube_sieve::__destruct -> Net_Sieve::disconnect -> Net_Sieve::_cmdLogout -> Net_Sieve::_doCmd -> Net_Sieve::_handleConnectAndLogin -> Net_Sieve::connect -> Net_Socket::connect -> Net_Socket::__call -> call_user_func_array()` | vendor/pear/pear-core-minimal/src/PEAR.php:223 |
| 49 | dispatch | 7 | `rcube_sieve::__destruct -> Net_Sieve::disconnect -> Net_Sieve::_cmdLogout -> Net_Sieve::_doCmd -> Net_Sieve::_handleConnectAndLogin -> Net_Sieve::connect -> Net_Sieve::_cmdCapability -> PEAR::__call -> call_user_func_array()` | vendor/pear/pear-core-minimal/src/PEAR.php:223 |

## Reproduce

```sh
scripts/gadget_graph.sh lab-roundcube/roundcubemail-1.6.11 --label roundcube-graph
```
