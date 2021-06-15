function f0() {
    'use strict';
    return this;
}
if (new f0() === this || typeof new f0() === 'undefined') {
    throw '\'this\' had incorrect value!';
}
