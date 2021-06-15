function f0() {
    return f1();
}
;
(function () {
    'use strict';
    Function('return f();')();
}());
function f1() {
    return f1.caller;
}
