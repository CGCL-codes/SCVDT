var v0 = 0;
if (v0 !== 0) {
    $ERROR('#1: var x = 0; eval("/*\\u000D multi line \\u000D comment \\u000D x = 1;*/"); x === 0. Actual: ' + v0);
}
