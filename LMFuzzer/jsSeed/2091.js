function f0() {
    'use strict';
    return this;
}
;
function f1() {
    return f0();
}
if (f1() !== undefined) {
    throw '\'this\' had incorrect value!';
}
