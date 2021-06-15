function f0() {
    return Reflect.apply(Array.prototype.push, [
        1,
        2
    ], [
        3,
        4,
        5
    ]) === 5;
}
if (!f0())
    throw new Error('Test failed');
