async function f0() {
    throw 1;
}
f0().then(function () {
    $DONE('Should not be called');
}, function (e) {
    assert.sameValue(e, 1);
    $DONE();
});
