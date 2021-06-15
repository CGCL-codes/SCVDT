function f0() {
    return [...[
            1,
            2,
            3
        ]][2] === 3;
}
if (!f0())
    throw new Error('Test failed');
