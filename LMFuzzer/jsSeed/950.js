function f0() {
    var v0, v1, v2 = [
            1,
            2
        ];
    return ([v0, v1] = v2) === v2;
}
if (!f0())
    throw new Error('Test failed');
