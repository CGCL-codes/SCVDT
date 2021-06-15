v0 = eval;
function f0() {
    this.eval = v0;
}
var v1 = function () {
    Object.seal(this);
    l;
};
try {
    v1();
} catch (r) {
}
f0();
try {
    v1();
} catch (r) {
    f0();
}
