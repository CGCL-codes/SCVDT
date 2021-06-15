function f0() {
    var v0 = 'y';
    return {
        [x]() {
            return 1;
        }
    }.y() === 1;
}
if (!f0())
    throw new Error('Test failed');
