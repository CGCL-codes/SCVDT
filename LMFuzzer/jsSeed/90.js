function f0() {
    [] = [
        1,
        2
    ];
    ({} = {
        a: 1,
        b: 2
    });
    return true;
}
if (!f0())
    throw new Error('Test failed');
