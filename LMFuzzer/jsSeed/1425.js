function f0() {
    return f1();
}
;
(function () {
    'use strict';
    f0.apply(undefined);
}());
function f1() {
    return f1.caller;
}
