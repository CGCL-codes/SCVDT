function f0() {
    var v0 = '';
    for (var v1 of '\u20BB7\u20BB6')
        v0 += v1 + ' ';
    return v0 === '\u20BB7 \u20BB6 ';
}
if (!f0())
    throw new Error('Test failed');
