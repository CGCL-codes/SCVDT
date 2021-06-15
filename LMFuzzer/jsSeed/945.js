try {
    v0 = v0;
} catch (e) {
    $ERROR('#1: Unicode characters in variable Identifier allowed');
}
var v0 = 1;
if (v0 !== 1) {
    $ERROR('#2: __var === 1. Actual:  __var ===' + v0);
}
