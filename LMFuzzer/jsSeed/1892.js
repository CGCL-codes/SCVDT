var v0 = 0;
if (v0 !== 0) {
    $ERROR('#1: var x = 0; eval("//\\u0020 single line \\u0020 comment \\u0020 x = 1;"); x === 0. Actual: ' + v0);
}
