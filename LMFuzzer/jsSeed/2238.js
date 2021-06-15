'use strict';
function f0() {
}
var v0 = {
    get x() {
        return f0(0);
    }
};
for (var v1 = 0; v1 < 10; ++v1)
    v0.x;
