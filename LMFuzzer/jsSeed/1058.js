var v0 = 0;
if (v0 !== 0) {
    $ERROR('#1: var x = 0; eval("//\\u0009 single line \\u0009 comment \\u0009 x = 1;"); x === 0. Actual: ' + v0);
}
