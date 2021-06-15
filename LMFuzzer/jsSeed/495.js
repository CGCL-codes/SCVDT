try {
    v0 = f0();
} catch (e) {
}
var v1 = 0;
function f0() {
    try {
        f0();
    } catch (e) {
        v1++;
        [];
    }
}
f0();
