var v0 = 2;
var v1 = {
    set foo(stuff) {
        'use strict';
        v0 = this;
    }
};
v1.foo = 3;
if (v0 !== v1) {
    throw '\'this\' had incorrect value!';
}
