var v0 = function () {
    'use strict';
    return typeof this;
};
if (v0() !== 'undefined') {
    throw '\'this\' had incorrect value!';
}
