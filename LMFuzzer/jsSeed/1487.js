var v0 = 0;
if ((v0 = 1) == v0 !== true) {
    $ERROR('#1: var x = 0; ((x = 1) == x) === true');
}
var v0 = 0;
if (v0 == (v0 = 1) !== false) {
    $ERROR('#2: var x = 0; (x == (x = 1)) === false');
}
