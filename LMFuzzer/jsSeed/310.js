function f0() {
    var {a} = { a: 1 };
    return a === 1;
}
if (!f0())
    throw new Error('Test failed');
