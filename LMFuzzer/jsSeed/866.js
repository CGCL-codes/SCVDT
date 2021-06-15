var v0 = 1;
var v1 = { a: 2 };
with (v1) {
    v2 = function () {
        return v0;
    }();
}
if (v2 !== 2) {
    $ERROR('#1: result === 2. Actual: result ===' + v2);
}
