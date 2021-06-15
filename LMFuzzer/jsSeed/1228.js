var v0 = function f(o) {
    o.x = 1;
    return o;
}(new Object()).x;
if (v0 !== 1) {
    $ERROR('#1: Check Function Expression for automatic semicolon insertion');
}
