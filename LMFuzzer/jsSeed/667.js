function f0() {
    arguments[0]['E'] = 2.74;
}
var v0 = {};
f0(v0);
if (v0.E !== 2.74) {
    $ERROR('#1: __obj.E === 2.74. Actual: __obj.E ===' + v0.E);
}
