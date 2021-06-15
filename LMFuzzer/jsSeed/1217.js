function f0() {
    arguments[0]['PI'] = 3.14;
}
var v0 = {};
f0(v0);
if (v0.PI !== 3.14) {
    $ERROR('#1: __obj.PI === 3.14. Actual: __obj.PI ===' + v0.PI);
}
