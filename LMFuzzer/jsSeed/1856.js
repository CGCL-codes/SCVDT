function f0() {
    'use strict';
    return this === undefined;
}
;
if (!f0.bind()()) {
    throw '\'this\' had incorrect value!';
}
