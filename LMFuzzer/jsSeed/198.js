var v0 = 1;
if ((v0 = 0) < v0 !== false) {
    $ERROR('#1: var x = 1; (x = 0) < x === false');
}
var v0 = 0;
if (v0 < (v0 = 1) !== true) {
    $ERROR('#2: var x = 0; x < (x = 1) === true');
}
