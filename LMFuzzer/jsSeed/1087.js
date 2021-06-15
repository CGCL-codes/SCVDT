function f0() {
    var v0;
    v0.a;
    v0 = {};
}
try {
    f0();
    assertEq(0, 1);
} catch (e) {
}
