'use strict';
let v0;
let v1 = {
    set foo(value) {
        v0 = value;
    }
};
Object.freeze(v1);
v1.foo = 42;
if (v0 != 42)
    throw 'Error: bad result: ' + v0;
