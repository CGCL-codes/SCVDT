var v0 = 0;
if (v0 !== 0) {
    $ERROR('#1: var x = 0; eval("/*\\u2028 multi line \\u2028 comment \\u2028 x = 1;*/"); x === 0. Actual: ' + v0);
}
