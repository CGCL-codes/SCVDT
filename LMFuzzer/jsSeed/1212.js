function f0() {
    this.a = 5;
    this.b = 2;
}
f0.prototype.add = function (x, y) {
    return x + y;
};
