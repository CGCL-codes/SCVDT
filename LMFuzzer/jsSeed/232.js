function f0() {
    'use strict';
    return this === undefined;
}
;
if (!f0.bind(undefined)()) {
    throw '\'this\' had incorrect value!';
}
