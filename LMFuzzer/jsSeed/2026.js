function f0() {
}
function f1() {
    f0();
    throw 123;
    f0();
}
f0();
f1();
f0();
