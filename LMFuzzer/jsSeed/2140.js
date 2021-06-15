var v0;
function f0() {
    try {
    } catch (err) {
        v0 = err;
    }
}
f0();
assert.sameValue(typeof v0, 'object');
assert.sameValue(v0.constructor, SyntaxError);
