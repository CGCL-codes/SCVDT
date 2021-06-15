var v0 = {};
function f0() {
    return this === v0;
}
;
if (!function () {
        'use strict';
        return f0.apply(v0);
    }()) {
    throw '\'this\' had incorrect value!';
}
