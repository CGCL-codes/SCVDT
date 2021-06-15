function f0() {
    var v0 = (v, w, x, y, z) => '' + v + w + x + y + z;
    return v0(6, 5, 4, 3, 2) === '65432';
}
if (!f0())
    throw new Error('Test failed');
