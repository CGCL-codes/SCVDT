var v0 = 0;
v0 = 1;
if (v0 !== 1) {
    $ERROR('#1: var x = 0; eval("// single line comment\\u000D x = 1;"); x === 1. Actual: ' + v0);
}
