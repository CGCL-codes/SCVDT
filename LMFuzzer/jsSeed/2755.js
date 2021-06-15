function f0() {
    'use strict';
    let v0 = 123;
    {
        let v0 = 456;
    }
    return v0 === 123;
}
if (!f0())
    throw new Error('Test failed');
