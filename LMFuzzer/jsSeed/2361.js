function f0(foo) {
    var v0;
    eval('this.__defineGetter__("y", function () { return x; })');
}
f0('');
try {
    (function () {
        throw y;
    }());
} catch (exc1) {
}
