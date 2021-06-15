function f0() {
    return 'tracejit,methodjit';
}
;
function f1(on) {
    f0('bar');
}
eval('test();function test() {  baz(true);  test();}');
