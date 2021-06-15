function f0() {
    return Math.max(...[
        1,
        2,
        3
    ]) === 3;
}
if (!f0())
    throw new Error('Test failed');
