var v0 = 4;
v0 >>>= 1;
if (v0 !== 2) {
    $ERROR('#1: var x = 4; x >>>= 1; x === 2. Actual: ' + v0);
}
v1 = 4;
v1 >>>= 1;
if (v1 !== 2) {
    $ERROR('#2: y = 4; y >>>= 1; y === 2. Actual: ' + v1);
}
