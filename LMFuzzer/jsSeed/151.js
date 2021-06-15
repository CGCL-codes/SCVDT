var v0 = {};
function f0() {
    'use strict';
    return this === v0;
}
;
if (!f0.bind(v0)()) {
    throw '\'this\' had incorrect value!';
}
