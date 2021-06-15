function f0() {
    return f2();
}
;
function f1() {
    'use strict';
    f0();
}
f1();
function f2() {
    return f2.caller;
}
