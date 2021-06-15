var v0 = 1;
v0 = 2;
function f0() {
    var v1 = { a: 1 };
    v0 = 'a';
    for (var v2 = v0; v2 < 2; v2++) {
        delete v1[v2];
    }
}
f0();
