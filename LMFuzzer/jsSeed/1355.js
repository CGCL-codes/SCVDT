var v0 = 500000;
var v1 = new Array(v0);
for (var v2 = 0; v2 < v0; v2++) {
    var v3 = {};
    v3.x = 42;
    delete v3.x;
    v1[v2] = v3;
}
