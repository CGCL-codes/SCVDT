function f0() {
    'use strict';
    return this === undefined;
}
;
if (!new Function('return f();')()) {
    throw '\'this\' had incorrect value!';
}
