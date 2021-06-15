function f0(obj) {
    return obj.nonexist;
}
for (var v0 = 0; v0 < 100; v0++) {
    var v1 = v0 % 2 ? v0 % 3 ? new Object() : new Object() : new Object();
    f0(v1);
}
