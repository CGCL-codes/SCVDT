function f0() {
    'use strict';
    return this === undefined;
}
;
if (!f0.apply(undefined)) {
    throw '\'this\' had incorrect value!';
}
