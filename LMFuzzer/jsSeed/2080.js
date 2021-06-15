function f0(a) {
    var v0 = 0;
    for (var v1 = 0; v1 < 500000; ++v1)
        v0 += a.valueOf();
    return v0;
}
var v0 = f0(5);
if (v0 != 2500000)
    throw 'Bad result: ' + v0;
