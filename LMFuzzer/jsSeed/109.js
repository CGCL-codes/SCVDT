function f0(__arg) {
    __arg.foo = 7;
}
var v0 = {};
f0(v0);
if (v0.foo !== 7) {
    $ERROR('#1: __obj.foo === 7. Actual: __obj.foo ===' + v0.foo);
}
