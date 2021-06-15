function f0() {
    try {
        String.prototype.length.x();
    } catch (e) {
    }
}
f0();
f0();
f0();
