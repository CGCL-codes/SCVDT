v0 = [];
function f0(o) {
    o[5] = {};
}
for (var v1 = 0; v1 < 20; v1++) {
    with (v0)
        f0(v0);
}
