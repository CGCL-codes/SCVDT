var v0 = {};
if (!isNaN(v0.foo++)) {
    $ERROR('#1: var __map={}; __map.foo === Not-a-Number. Actual: ' + v0.foo);
}
if (!('foo' in v0)) {
    $ERROR('#2: var __map={}; "foo" in __map');
}
