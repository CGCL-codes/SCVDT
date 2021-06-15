Number.prototype.negate = function () {
    'use strict';
    return -this;
};
for (var v0 = 1; v0 < 10000; ++v0)
    (268435455 * 100000).negate();
