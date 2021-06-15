'use strict';
var v0 = Function('return typeof this;');
if (v0() === 'undefined') {
    throw '\'this\' had incorrect value!';
}
