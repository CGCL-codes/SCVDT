let v0 = {
    set foo(x) {
        'use strict';
        return f0();
    }
};
function f0() {
    return 20;
}
for (let v1 = 0; v1 < 100000; v1++)
    v0.foo = 20;
