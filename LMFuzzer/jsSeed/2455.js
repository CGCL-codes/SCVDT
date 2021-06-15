v0 = [1];
v1 = [];
v0.__defineGetter__(0, function () {
    v1.length = 4294967295;
});
v2 = v0.concat(v1);
for (var v3 = 0; v3 < 20; v3++) {
    assertEquals(undefined, v2[v3]);
}
