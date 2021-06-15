function f0(__arg) {
    __arg.foo = 'whiskey gogo';
}
var v0 = {};
f0(v0);
if (v0.foo !== 'whiskey gogo') {
    $ERROR('#1: __obj.foo === "whiskey gogo". Actual: __obj.foo ===' + v0.foo);
}
