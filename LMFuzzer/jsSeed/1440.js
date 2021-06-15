function f0() {
    return this !== undefined;
}
;
if (!function () {
        'use strict';
        return f0.apply();
    }()) {
    throw '\'this\' had incorrect value!';
}
