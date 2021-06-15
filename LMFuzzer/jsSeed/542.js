function f0(a) {
    for (var v0 = 0; v0 < a.length; v0++) {
        var v1 = Math.fround(Math.random());
        a[v0] = v1;
    }
}
f0(new Array(2048));
f0(new Uint8ClampedArray(2048));
