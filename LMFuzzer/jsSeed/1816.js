function f0() {
    var v0 = { x: true };
    for (var v1 = 0; v1 < 10; v1++) {
        delete v0.x;
    }
}
f0();
