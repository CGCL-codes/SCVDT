function f0(str, count) {
    var v0 = str.repeat(count);
    return v0[0] + v0[count >> 1] + v0[v0.length - 1];
}
for (var v1 = 0; v1 < 10000; ++v1)
    f0(v1.toString(), 100);
