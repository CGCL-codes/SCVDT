function f0() {
    'use strict';
    return this;
}
;
if (f0.bind(this)() !== this) {
    throw '\'this\' had incorrect value!';
}
