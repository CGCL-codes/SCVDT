function f0() {
    var v0 = [10];
    try {
        f0();
    } catch (e) {
        v0.map(v => v + 1);
    }
}
f0();
