var v0 = 1;
v0 &= 1;
if (v0 !== 1) {
    $ERROR('#1: var x = 1; x &= 1; x === 1. Actual: ' + v0);
}
v1 = 1;
v1 &= 1;
if (v1 !== 1) {
    $ERROR('#2: y = 1; y &= 1; y === 1. Actual: ' + v1);
}
