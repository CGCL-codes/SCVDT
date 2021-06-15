function f0() {
}
f0();
var v0 = {
    get foo() {
        f0();
        throw 123;
        f0();
    }
};
v0.foo;
f0();
