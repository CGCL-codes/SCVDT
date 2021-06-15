var v0 = 0;
if (v0 !== 0) {
    $ERROR('#1: var x = 0; eval("/*\\u000B multi line \\u000B comment \\u000B x = 1;*/"); x === 0. Actual: ' + v0);
}
