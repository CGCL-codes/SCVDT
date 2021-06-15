var v0 = 0;
if ((v0 = 1) !== 1) {
    $ERROR('#1: var x = 0; (x = 1) === 1. Actual: ' + (v0 = 1));
}
v0 = 0;
if ((v0 = 1) !== 1) {
    $ERROR('#2: x = 0; (x = 1) === 1. Actual: ' + (v0 = 1));
}
