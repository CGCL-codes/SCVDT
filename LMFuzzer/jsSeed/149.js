var v0 = function f(o) {
    o.x = 1;
    return o;
};
new Object().x;
if (typeof v0 !== 'function') {
    $ERROR('#1: Check Function Expression for automatic semicolon insertion');
}
