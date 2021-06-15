{
    function f0() {
        v0 = 1;
    }
    assert.throws(ReferenceError, function () {
        f0();
    });
    let v0;
}
