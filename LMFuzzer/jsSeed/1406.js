function f0() {
    try {
        new {
            x: function () {
            }
        }.x()();
    } catch (e) {
    }
}
for (var v0 = 0; v0 < 10000; v0++) {
    f0();
}
