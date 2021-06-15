function f0(expected, actual) {
    if (expected != actual) {
    }
}
function f1(funcName) {
    return f0(undefined, '');
}
f0('', '');
f1();
