function f0() {
    return f1();
}
;
var v0 = {};
(function () {
    'use strict';
    f0.call(v0);
}());
function f1() {
    return f1.caller;
}
