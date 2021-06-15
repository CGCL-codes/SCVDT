var v0 = new Uint8ClampedArray(10 * 1024 * 1024);
var v1 = 0;
for (var v2 = 0; v2 < 10000; v2++)
    v1 += v0[v2];
