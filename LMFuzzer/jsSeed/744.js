function f0() {
    this.b = function () {
    };
    this.b = Object.e;
    Object.defineProperty(this, 'b', {});
}
for (a in [
        0,
        0,
        0,
        0
    ]) {
    new f0();
}
