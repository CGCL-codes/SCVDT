var v0 = this;
function f0() {
    return f1();
}
;
(function () {
    'use strict';
    f0.bind(v0)();
}());
function f1() {
    return f1.caller;
}
