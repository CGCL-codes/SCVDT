function f0() {
    'use strict';
    return this === undefined && {
        a: 1,
        a: 1
    }.a === 1;
}
if (!f0())
    throw new Error('Test failed');
