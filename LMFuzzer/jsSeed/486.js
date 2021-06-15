'use strict';
var v0 = 2;
var v1 = {
    set foo(stuff) {
        v0 = this;
    }
};
v1.foo = 3;
if (v0 !== v1) {
    throw '\'this\' had incorrect value!';
}
