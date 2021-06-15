var v0 = this;
function f0() {
    return this === v0;
}
;
if (!function () {
        'use strict';
        return f0.call();
    }()) {
    throw '\'this\' had incorrect value!';
}
