if (isNaN(-NaN) !== true) {
    $ERROR('#1: -NaN === Not-a-Number. Actual: ' + -NaN);
}
var v0 = NaN;
if (isNaN(-v0) != true) {
    $ERROR('#2: var x = NaN; -x === Not-a-Number. Actual: ' + -v0);
}
