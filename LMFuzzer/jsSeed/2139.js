function f0() {
    return 'tracejit,methodjit';
}
;
function f1(on) {
    f0('bar');
}
f2();
function f2() {
    f1(true);
    f2();
}
