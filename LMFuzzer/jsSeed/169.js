function f0() {
    'use strict';
    return this;
}
;
if (f0.apply(this) !== this) {
    throw '\'this\' had incorrect value!';
}
