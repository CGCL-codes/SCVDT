var v0 = { count: 24 };
var v1 = 'count';
for (var v2 = 0; v2 < 1024; ++v2) {
    var v3 = v0[v1];
    if (v2 === 2)
        v0.newAttr = 42;
}
