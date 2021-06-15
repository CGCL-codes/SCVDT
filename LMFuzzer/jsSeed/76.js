function f0(expected, actual) {
    return expected != actual;
}
function f1() {
    f0(true, true);
}
f0('', '');
f1();
