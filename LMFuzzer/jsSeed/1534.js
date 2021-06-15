function f0() {
    'use strict';
    for (var v0 in this) {
        assert.notSameValue(v0, 'caller', 'tempIndex');
    }
}
f0.call(f0);
