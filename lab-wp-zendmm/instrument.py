#!/usr/bin/env python3
"""
Rung-1 instrumentation for the CVE-2026-109619 weaponization research lab
(lab-zendmm-fpm). Applied to the official php-8.2.34 source before build.

Prints (worker stderr -> FPM catch_workers_output -> docker logs):
  [UAFDBG] INIT    d=<ptr> lock=<n> level=<n>   php_var_unserialize_init:
          the fresh emalloc or the stale pointer returned to the caller
  [UAFDBG] DESTROY d=<ptr> lock=<n> level=<n>   php_var_unserialize_destroy
  [UAFDBG] SESS    data=<ptr> len=<n>           session bytes handed to the
          serializer decoder (the reclaim candidate allocation)
  [UAFDBG] WRAP    d=<ptr> last=<ptr>           php_var_unserialize wrapper:
          the stale bookkeeping dereference point ((*var_hash)->last)
  [UAFDBG] RREF    id=.. entries=.. used=..     var_access: the R:/r:
          reference lookup — where the forged entries list materializes

The WRAP/RREF prints are gated on !BG(serialize_lock) && level > 1 so they
only fire during stale/nested consumption (not ordinary fresh decodes).
"""
import sys

path = sys.argv[1] + "/ext/standard/var_unserializer.c"
src = open(path).read()
n_applied = 0


def patch(anchor, replacement, what):
    global src, n_applied
    if anchor not in src:
        sys.exit(f"instrument.py: anchor not found for: {what}")
    src = src.replace(anchor, replacement, 1)
    n_applied += 1


# 1. DESTROY: print d/lock/level at entry
patch(
    "PHPAPI void php_var_unserialize_destroy(php_unserialize_data_t d) {\n",
    'PHPAPI void php_var_unserialize_destroy(php_unserialize_data_t d) {\n'
    '\tfprintf(stderr, "[UAFDBG] DESTROY d=%p lock=%u level=%u\\n",'
    ' (void*)d, BG(serialize_lock), BG(unserialize).level);\n',
    "destroy head")

# 2. INIT: print the returned d just before return
patch(
    "\t} else {\n"
    "\t\td = BG(unserialize).data;\n"
    "\t\t++BG(unserialize).level;\n"
    "\t}\n"
    "\treturn d;\n"
    "}",
    "\t} else {\n"
    "\t\td = BG(unserialize).data;\n"
    "\t\t++BG(unserialize).level;\n"
    "\t}\n"
    '\tfprintf(stderr, "[UAFDBG] INIT d=%p lock=%u level=%u\\n",'
    ' (void*)d, BG(serialize_lock), BG(unserialize).level);\n'
    "\treturn d;\n"
    "}",
    "init tail")

# 3. wrapper: the stale-state dereference point — print BEFORE the
# dereference (the deref of forged bytes is expected to segfault during
# reclaim calibration; the print must survive it)
patch(
    "\tvar_entries *orig_var_entries = (*var_hash)->last;\n"
    "\tzend_long orig_used_slots = orig_var_entries"
    " ? orig_var_entries->used_slots : 0;\n",
    "\tvar_entries *orig_var_entries = (*var_hash)->last;\n"
    '\tfprintf(stderr, "[UAFDBG] WRAP d=%p last=%p\\n",'
    ' (void*)(*var_hash), (void*)orig_var_entries);\n'
    "\tzend_long orig_used_slots = orig_var_entries"
    " ? orig_var_entries->used_slots : 0;\n"
    '\tif (!BG(serialize_lock) && BG(unserialize).level > 1) {\n'
    '\t\tfprintf(stderr, "[UAFDBG] WRAP2 d=%p last=%p used=%ld\\n",'
    ' (void*)(*var_hash), (void*)orig_var_entries, (long)orig_used_slots);\n'
    '\t}\n',
    "unserialize wrapper")

# 4. var_access: the R:/r: lookup against the (possibly forged) entries,
#    including the returned zval's type and value (the weaponized read).
anchor_va = ("static zval *var_access(php_unserialize_data_t *var_hashx, zend_long id)\n"
             "{\n"
             "\tvar_entries *var_hash = &(*var_hashx)->entries;\n")
if anchor_va not in src:
    sys.exit("instrument.py: anchor not found for: var_access head")
ret_anchor = "\tif (id < 0 || id >= var_hash->used_slots) return NULL;\n\n\treturn var_hash->data[id];\n}"
if ret_anchor not in src:
    sys.exit("instrument.py: anchor not found for: var_access return")
src = src.replace(
    ret_anchor,
    "\tif (id < 0 || id >= var_hash->used_slots) return NULL;\n"
    "\n"
    '\tif (!BG(serialize_lock) && BG(unserialize).level > 1) {\n'
    '\t\tfprintf(stderr, "[UAFDBG] RVAL id=%ld zval=%p type=%u lval=0x%lx\\n",'
    ' (long)id, (void*)var_hash->data[id],\n'
    '\t\t\t(unsigned)Z_TYPE_P(var_hash->data[id]),'
    ' (unsigned long)Z_LVAL_P(var_hash->data[id]));\n'
    "\t}\n"
    "\treturn var_hash->data[id];\n}",
    1)
patch(
    anchor_va,
    anchor_va
    + '\tif (!BG(serialize_lock) && BG(unserialize).level > 1) {\n'
    '\t\tfprintf(stderr, "[UAFDBG] RREF id=%ld entries=%p used=%ld\\n",'
    ' (long)id, (void*)var_hash, (long)var_hash->used_slots);\n'
    '\t}\n',
    "var_access")

# 5b. dtor-path visibility (rung 4): print the block, negative count,
# selected slot, and the written zval in tmp_var / var_push_dtor_value.
anchor_dt = ("static zend_always_inline zval *tmp_var(php_unserialize_data_t *var_hashx, zend_long num)\n"
             "{\n")
if anchor_dt not in src:
    sys.exit("instrument.py: anchor not found for: tmp_var head")
src = src.replace(
    anchor_dt,
    anchor_dt
    + '\tfprintf(stderr, "[UAFDBG] DTVAR nump=%ld last_dtor=%p used=%ld\\n",'
    ' (long)num, (void*)(*var_hashx)->last_dtor,'
    ' (*var_hashx)->last_dtor ? (long)(*var_hashx)->last_dtor->used_slots : -1);\n',
    1)
anchor_pv = ("static zend_never_inline void var_push_dtor_value(php_unserialize_data_t *var_hashx, zval *rval)\n"
             "{\n")
if anchor_pv not in src:
    sys.exit("instrument.py: anchor not found for: var_push_dtor_value head")
src = src.replace(
    anchor_pv,
    anchor_pv
    + '\tfprintf(stderr, "[UAFDBG] DTPUSH type=%u val=0x%lx\\n",'
    ' (unsigned)Z_TYPE_P(rval), (unsigned long)Z_LVAL_P(rval));\n',
    1)

open(path, "w").write(src)

# 5c. object-destruction call path (rung 5): print the object, its
# handlers table, and the handler function pointers about to be called
# — so a real object's destruction calibrates the fake, and a forged
# handlers table shows the sentinel pointer in the log before the crash.
#
# Rung 5b calibration oracle: also print the runtime address of
# zif_system (ext/standard/exec.c — always compiled in, even with
# --disable-all) so the lab POC can forge a call-shape-compatible
# terminal target. This is the LAB analog of the public exploits'
# OOM-message / PS(id)->cookie leak stages, which this repo
# deliberately does not reproduce (repo scope: fixed benign command,
# no arbitrary-target packaging — see ANALYSIS 0.9).
opath = sys.argv[1] + "/Zend/zend_objects_API.c"
osrc = open(opath).read()
# Insert the rung-5b calibration oracle AFTER the file's own includes
# (prepending before php's headers left zend_execute_data/zval/zif_system
# undeclared at that point — build break, fixed 2026-10-21).
inc_anchor = '#include "zend_API.h"'
if inc_anchor not in osrc:
    sys.exit("instrument.py: anchor not found for: zend_API.h include")
osrc = osrc.replace(
    inc_anchor,
    inc_anchor + "\n"
    "#include <stdint.h> /* UAFDBG */\n"
    "/* UAFDBG: rung-5b calibration oracle — plain extern decl (zend_execute_data\n"
    " * and zval are known here, after zend_API.h; the PHP_FUNCTION/ZEND_FUNCTION\n"
    " * macro chain mis-expands in this TU — build break, fixed 2026-10-21) */\n"
    "void zif_system(zend_execute_data *execute_data, zval *return_value);\n",
    1)
anchor_od = ("ZEND_API void ZEND_FASTCALL zend_objects_store_del(zend_object *object) /* {{{ */\n"
             "{\n")
if anchor_od not in osrc:
    sys.exit("instrument.py: anchor not found for: zend_objects_store_del head")
osrc = osrc.replace(
    anchor_od,
    anchor_od
    + '\tfprintf(stderr, "[UAFDBG] OBJDEL obj=%p rc=%u handlers=%p"\n'
    '\t\t" dtor_obj=%p free_obj=%p zsys=%p\\n",'
    ' (void*)object, (unsigned)GC_REFCOUNT(object),\n'
    '\t\t(const void*)object->handlers,\n'
    '\t\tobject->handlers ? (const void*)object->handlers->dtor_obj : NULL,\n'
    '\t\tobject->handlers ? (const void*)object->handlers->free_obj : NULL,\n\t\t(void*)(uintptr_t)zif_system);\n',
    1)
open(opath, "w").write(osrc)
n_applied += 1

# 5d. refcount-zero destruction trace (rung 5): every rc_dtor_func entry
# — shows which engine paths destroy which zvals at request shutdown.
vpath = sys.argv[1] + "/Zend/zend_variables.c"
vsrc = open(vpath).read()
anchor_rc = ("ZEND_API void ZEND_FASTCALL rc_dtor_func(zend_refcounted *p)\n"
             "{\n")
if anchor_rc not in vsrc:
    sys.exit("instrument.py: anchor not found for: rc_dtor_func head")
vsrc = vsrc.replace(
    anchor_rc,
    anchor_rc
    + '\tfprintf(stderr, "[UAFDBG] RCDTOR type=%u p=%p\\n",'
    ' (unsigned)GC_TYPE(p), (void*)p);\n',
    1)
open(vpath, "w").write(vsrc)
n_applied += 1

# 5e. ZendMM: trace 3-page-class allocations (the freed bookkeeping's
# size class) at the success return of zend_mm_alloc_pages, plus the
# best-fit candidate at selection time (researching why the session-read
# reclaim misses the freed bookkeeping's run).
#
# TOLERANT (non-fatal): these anchors sit in zend_alloc.c internals,
# which the 2026-10-21 security patch reworked heavily (OOM longjmp
# removal — ANALYSIS §0.1). On patched sources (8.2.35+) the anchors
# may be absent; skipping these prints is fine because they only
# calibrate reclaim page positions on the VULNERABLE build — the
# negative-control run on patched sources needs only the
# INIT/DESTROY/SESS/WRAP/RVAL/OBJDEL prints above, all of which
# remain strict.
apath = sys.argv[1] + "/Zend/zend_alloc.c"
asrc = open(apath).read()
n_alloc_applied = 0
anchor3 = ("\t\t\t\t/* find first 1 bit */\n"
           "\t\t\t\tlen = i + zend_ulong_ntz(tmp) - page_num;\n"
           "\t\t\t\tif (len >= pages_count) {\n"
           "\t\t\t\t\tif (len == pages_count) {\n"
           "\t\t\t\t\t\tgoto found;\n")
if anchor3 in asrc:
    asrc = asrc.replace(
        anchor3,
        "\t\t\t\t/* find first 1 bit */\n"
        "\t\t\t\tlen = i + zend_ulong_ntz(tmp) - page_num;\n"
        '\t\t\t\tif (pages_count == 3 && page_num >= 100 && page_num <= 140) {\n'
        '\t\t\t\t\tfprintf(stderr, "[UAFDBG] RUN page=%lu len=%lu\\n",'
        ' (unsigned long)page_num, (unsigned long)len);\n'
        "\t\t\t\t}\n"
        "\t\t\t\tif (len >= pages_count) {\n"
        "\t\t\t\t\tif (len == pages_count) {\n"
        "\t\t\t\t\t\tgoto found;\n",
        1)
    n_alloc_applied += 1
else:
    print("instrument.py: WARN: best-fit run anchor absent "
          "(patched zend_alloc? skipping RUN trace)")
anchor = ("found:\n"
          "\tif (steps > 2 && pages_count < 8) {")
if anchor in asrc:
    asrc = asrc.replace(
        anchor,
        'found:\n'
        '\tif (pages_count == 3) {\n'
        '\t\tfprintf(stderr, "[UAFDBG] PAGES3 chunk=%p page_num=%lu addr=%p\\n",'
        ' (void*)chunk, (unsigned long)page_num,'
        ' (void*)ZEND_MM_PAGE_ADDR(chunk, page_num));\n'
        '\t}\n'
        "\tif (steps > 2 && pages_count < 8) {",
        1)
    n_alloc_applied += 1
else:
    print("instrument.py: WARN: zend_mm_alloc_pages found: anchor absent "
          "(patched zend_alloc? skipping PAGES3 trace)")
open(apath, "w").write(asrc)
if n_alloc_applied:
    n_applied += 1
else:
    print("instrument.py: WARN: no zend_alloc traces applied "
          "(expected on patched sources)")

# 5. session.c: the session bytes handed to the decoder (reclaim candidate)
spath = sys.argv[1] + "/ext/session/session.c"
ssrc = open(spath).read()
anchor = "static zend_result php_session_decode(zend_string *data) /* {{{ */\n{\n"
if anchor not in ssrc:
    sys.exit("instrument.py: anchor not found for: session decode head")
ssrc = ssrc.replace(
    anchor,
    'static zend_result php_session_decode(zend_string *data) /* {{{ */\n{\n'
    '\tfprintf(stderr, "[UAFDBG] SESS data=%p len=%zu\\n",'
    ' (void*)ZSTR_VAL(data), ZSTR_LEN(data));\n',
    1)
open(spath, "w").write(ssrc)
n_applied += 1

print(f"instrument.py: {n_applied} patches applied")
