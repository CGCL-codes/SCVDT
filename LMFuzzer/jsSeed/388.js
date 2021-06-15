function f0() {
    return f1();
}
;
(function () {
    'use strict';
    f0.bind()();
}());
function f1() {
    return f1.caller;
}
