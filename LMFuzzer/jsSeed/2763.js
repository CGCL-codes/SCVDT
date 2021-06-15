var v0 = { p1: 1 };
var v1 = {
    p1: 1,
    p2: 2
};
for (var v2 in v0) {
    for (var v3 in v1) {
        delete v1.p2;
    }
}
