if (true !== true) {
    $ERROR('#1: (true) === true');
}
var v0 = new Boolean(true);
if (v0 !== v0) {
    $ERROR('#2: var x = new Boolean(true); (x) === x. Actual: ' + v0);
}
