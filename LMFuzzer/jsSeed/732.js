var v0;
eval('x = 1', 'x = 2');
if (v0 !== 1) {
    $ERROR('#1: eval("x = 1", "x = 2"); x === 1. Actual: ' + v0);
}
