var v0 = 1 + function (t) {
    return { a: t };
}(2 + 3).a;
if (v0 !== 6) {
    $ERROR('#1: Check Function Expression for automatic semicolon insertion');
}
