if (f0() !== 'unicode') {
    $ERROR('#1: __func() === "unicode". Actual:  __func() ===' + f0());
}
function f0() {
    return 'ascii';
}
;
function f0() {
    return 'unicode';
}
;
