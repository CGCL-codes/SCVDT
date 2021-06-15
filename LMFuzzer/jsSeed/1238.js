function f0() {
    v0 = v2;
}
for (var v1 in [
        1,
        2
    ]) {
    try {
        new f0(v1);
    } catch (e) {
    }
}
let v2 = undefined;
WScript.Echo('PASS');
