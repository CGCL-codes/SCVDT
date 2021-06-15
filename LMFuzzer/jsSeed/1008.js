var v0 = 1;
if (v0 !== 1) {
    $ERROR('#1: eval("\\u0020var x\\u0020= 1\\u0020"); x === 1. Actual: ' + v0);
}
var v0 = 1;
if (v0 !== 1) {
    $ERROR('#2:  var x = 1 ; x === 1. Actual: ' + v0);
}
