function f0(string) {
    var v0;
    for (var v1 = 0; v1 < 1000000; ++v1)
        v0 = string[0];
    return v0;
}
var v0 = f0('x');
if (v0 != 'x')
    throw 'Bad result: ' + v0;
