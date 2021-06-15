'use strict';
var v0 = {
    get foo() {
        return this;
    }
};
if (v0.foo !== v0) {
    throw '\'this\' had incorrect value!';
}
