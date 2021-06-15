try {
    this.__defineGetter__('x', Iterator)();
} catch (e) {
}
v0 = function () {
    return function () {
        this.x;
    };
}();
try {
    v0();
} catch (e) {
}
v0();
