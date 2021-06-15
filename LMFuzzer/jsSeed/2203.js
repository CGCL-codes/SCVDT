var v0 = this;
function f0() {
    return this === v0;
}
;
if (!function () {
        'use strict';
        return f0.apply(undefined);
    }()) {
    throw '\'this\' had incorrect value!';
}
