function f0(a, b) {
    return a + b;
}
for (var v0 = 0; v0 < 100000; ++v0) {
    var v1 = f0(1, 2, 3);
    if (v1 != 3)
        throw 'Bad result: ' + v1;
}
