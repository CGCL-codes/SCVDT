function f0(foo) {
    var v0;
    this.__defineGetter__('y', function () {
        return v0;
    });
}
f0('');
try {
    (function () {
        throw y;
    }());
} catch (exc1) {
}
