var v0 = 3;
function f0() {
    'use strict';
    v0 = this;
    return 'a';
}
if ('ab'.replace('b', f0) !== 'aa' || v0 !== undefined) {
    throw '\'this\' had incorrect value!';
}
