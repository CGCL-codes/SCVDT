var v0 = {
    toString: function () {
        return 'abc';
    }
};
assert.sameValue(String.prototype.trim.call(v0), 'abc', 'String.prototype.trim.call(obj)');
