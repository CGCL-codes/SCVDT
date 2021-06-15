assert.throws(TypeError, function () {
    WeakMap.prototype.set.call(Symbol(), {}, 1);
});
assert.throws(TypeError, function () {
    var v0 = new WeakMap();
    v0.set.call(Symbol(), {}, 1);
});
