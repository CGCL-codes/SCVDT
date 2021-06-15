var v0;
if (v0 !== undefined) {
    $ERROR('#1: var x; x === undefined. Actual: ' + v0);
}
v0++;
if (v0 === undefined) {
    $ERROR('#2: var x; x++; x !== undefined');
}
