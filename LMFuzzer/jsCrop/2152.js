function f0() {
    return {
        y() {
            return 2;
        }
    }.y() === 2;
}
if (!f0())
    throw new Error('Test failed');
