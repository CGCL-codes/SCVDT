function f0() {
}
f0();
var v0 = {
    func: function () {
        f0();
        throw 123;
        f0();
    }
};
v0.func();
f0();
