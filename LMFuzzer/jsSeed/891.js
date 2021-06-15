var v0 = 0;
if (v0 !== 0) {
    $ERROR('#1: var x = 0; eval("/*\\u000A multi line \\u000A comment \\u000A x = 1;*/"); x === 0. Actual: ' + v0);
}
