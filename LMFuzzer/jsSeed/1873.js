function f0() {
    var v0 = function () {
        'use strict';
        return this;
    };
    return new v0() !== fnGlobalObject() && typeof new v0() !== 'undefined';
}
runTestCase(f0);
