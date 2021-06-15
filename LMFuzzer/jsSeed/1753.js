var v0 = 1;
var v1 = delete v0;
if (v1) {
    $ERROR('#1: y = 1; (delete y) === false. Actual: ' + v1);
}
;
if (v0 !== 1) {
    $ERROR('#2: y = 1; delete y; y === 1. Actual: ' + v0);
}
