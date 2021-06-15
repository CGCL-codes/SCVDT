'use strict';
var v0 = new Function('return typeof this;');
if (v0() === 'undefined') {
    throw '\'this\' had incorrect value!';
}
