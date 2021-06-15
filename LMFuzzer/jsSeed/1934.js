function f0() {
    'use strict';
    return typeof this;
}
if (f0() !== 'undefined') {
    throw '\'this\' had incorrect value!';
}
