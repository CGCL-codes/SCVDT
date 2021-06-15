function f0() {
    'use strict';
    return this;
}
;
if (f0.call(this) !== this) {
    throw '\'this\' had incorrect value!';
}
