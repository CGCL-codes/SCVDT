async function f0() {
    var v0 = {};
    var v1 = false;
    try {
        await Promise.reject(v0);
    } catch (e) {
        v1 = true;
        assert.sameValue(e, v0);
    }
    assert(v1);
}
