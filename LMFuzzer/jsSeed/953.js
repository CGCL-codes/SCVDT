var v0 = this;
function f0() {
    return this;
}
;
if (function () {
        'use strict';
        return f0.apply(v0);
    }() !== v0) {
    throw '\'this\' had incorrect value!';
}
