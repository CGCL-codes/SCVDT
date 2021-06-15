function f0() {
    return arguments.length;
}
for (var v0 = 0; v0 < 100000; ++v0) {
    var v1 = f0(11, 12, 13, 18, 19, 20);
    if (v1 != 6)
        throw 'Error: ' + v1;
}
