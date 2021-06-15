function f0() {
    ['z'].forEach(function () {
        Object.freeze(Array.prototype.forEach);
    });
}
f0();
