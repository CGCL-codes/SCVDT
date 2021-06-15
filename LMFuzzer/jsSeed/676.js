function f0() {
    return this !== undefined;
}
;
function f1() {
    'use strict';
    return f0();
}
if (!f1()) {
    throw '\'this\' had incorrect value!';
}
