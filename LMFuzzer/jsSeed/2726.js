function f0(x, y) {
    return +(x ? x : y), y >>> 0;
}
f0(0, -0);
f0(0, 2147483649);
