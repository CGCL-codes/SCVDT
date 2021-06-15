function f0() {
    if (!this)
        return false;
    label:
        function f1() {
            return 2;
        }
    return f1() === 2;
}
if (!f0())
    throw new Error('Test failed');
