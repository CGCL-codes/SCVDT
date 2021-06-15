function f0() {
    'use strict';
    return this === undefined;
}
;
if (!f0.call()) {
    throw '\'this\' had incorrect value!';
}
