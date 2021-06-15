var v0 = { x: {} };
function f0() {
    var v1 = v0;
    for (var v2 = 0; v2 < 10; v2++) {
        v0 = v1.x;
    }
}
f0();
