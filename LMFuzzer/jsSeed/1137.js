var v0 = 1;
var v1 = function () {
    return v0;
};
var v2 = { a: 2 };
with (v2) {
    v3 = v1();
}
if (v3 !== 1) {
    $ERROR('#1: result === 1. Actual: result ===' + v3);
}
