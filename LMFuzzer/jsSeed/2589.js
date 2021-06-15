function f0() {
    return f1();
}
;
(function () {
    'use strict';
    return eval('f();');
}());
function f1() {
    return f1.caller;
}
