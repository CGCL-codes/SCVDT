var v0 = 1;
if (delete v0) {
    $ERROR('#1: y = 1; (delete y) === false. Actual: ' + delete v0);
}
;
if (v0 !== 1) {
    $ERROR('#2: y = 1; delete y; y === 1. Actual: ' + v0);
}
