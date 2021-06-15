var v0 = new Proxy(function () {
    return function () {
        foo;
    }();
}, {});
try {
    new v0();
} catch (e) {
}
