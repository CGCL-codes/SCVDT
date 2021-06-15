var v0 = '//' + new Array(1024).join('x');
try {
    eval(v0 + '\nfunction f() { for (x : y) { } }');
    throw 'not reached';
} catch (e) {
    if (!(e instanceof SyntaxError))
        throw e;
}
