var v0 = 0;
if (v0 !== 0) {
    $ERROR('#1: var x = 0; eval("//\\u00A0 single line \\u00A0 comment \\u00A0 x = 1;"); x === 0. Actual: ' + v0);
}
