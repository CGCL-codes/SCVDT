function f0(a, b) {
    return a - b;
}
var v0 = 0;
for (var v1 = 0; v1 < 1000000; ++v1)
    v0 += f0('42', v1);
if (v0 != -499957500000)
    throw 'Bad result: ' + v0;
