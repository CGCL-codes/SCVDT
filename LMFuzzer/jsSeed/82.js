var v0 = 0;
if (v0 !== 0) {
    $ERROR('#1: var x = 0; eval("//\\u000C single line \\u000C comment \\u000C x = 1;"); x === 0. Actual: ' + v0);
}
