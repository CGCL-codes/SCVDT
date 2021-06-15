function f0() {
    var v0 = '';
    for (var v1 = 0; v1 < 5000; v1++)
        v0 += 'x' + v1 + '=' + v1 + ';\n';
    return v0;
}
eval(f0());
