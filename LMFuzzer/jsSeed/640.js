var v0 = function () {
    'use strict';
    return this;
};
if (new v0() === this || typeof new v0() === 'undefined') {
    throw '\'this\' had incorrect value!';
}
