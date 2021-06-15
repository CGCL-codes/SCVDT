function f0() {
    return this !== undefined;
}
;
if (!function () {
        return new Function('"use strict";return f();')();
    }()) {
    throw '\'this\' had incorrect value!';
}
