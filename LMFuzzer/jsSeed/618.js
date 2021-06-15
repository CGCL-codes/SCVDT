var v0 = { foo: 'bar' };
v0.foo++;
if (!isNaN(v0.foo)) {
    $ERROR('#1: var __map={foo:"bar"}; __map.foo++; __map.foo === Not-a-Number. Actual: ' + v0.foo);
}
