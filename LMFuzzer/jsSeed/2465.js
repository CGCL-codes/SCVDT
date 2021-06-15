function f0() {
    return this !== undefined;
}
;
if (!function () {
        'use strict';
        return eval('f();');
    }()) {
    throw '\'this\' had incorrect value!';
}
