function f0(x) {
    return '' + x;
}
var v0;
var v1 = 100000;
for (var v2 = 0; v2 < v1; ++v2)
    v0 = f0(v2);
if (v0 != String(v1 - 1))
    throw 'Error: bad result: ' + v0;
