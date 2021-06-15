var v0 = 0;
if ((v0 = 1) > v0 !== false) {
    $ERROR('#1: var x = 0; (x = 1) > x === false');
}
var v0 = 1;
if (v0 > (v0 = 0) !== true) {
    $ERROR('#2: var x = 1; x > (x = 0) === true');
}
