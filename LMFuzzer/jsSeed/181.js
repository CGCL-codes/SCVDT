var v0 = new Proxy(function () {
    return function () {
        eval('foo');
    }();
}, {});
try {
    new v0();
} catch (e) {
}
