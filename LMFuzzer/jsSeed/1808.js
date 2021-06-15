function f0() {
    var v0 = 1, v1;
    for (var v2 = 0; v2 < 50000; ++v2)
        v1 <<= v0 / 3;
}
RegExp({ toString: f0 });
