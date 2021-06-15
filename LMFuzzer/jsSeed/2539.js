function f0(str, count) {
    return str.repeat(count);
}
for (var v0 = 0; v0 < 10000; ++v0)
    f0(v0.toString(), v0);
