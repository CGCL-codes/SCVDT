function f0() {
    try {
        var v0 = {};
        throw 12;
    } catch (e) {
        v0.x = 5;
    }
}
f0();
f0();
f0();
