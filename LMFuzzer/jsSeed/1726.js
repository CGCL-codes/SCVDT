function f0() {
    with ({}) {
    }
    with ({ x: 42 }) {
        var f0 = function () {
            'use strict';
            return x;
        };
    }
    with ({}) {
    }
}
