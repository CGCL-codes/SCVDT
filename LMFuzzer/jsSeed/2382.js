function f0(t) {
    return t;
}
var v0 = 1 + f0(2 + 3);
if (v0 !== 6) {
    $ERROR('#1: Check Function Expression for automatic semicolon insertion');
}
