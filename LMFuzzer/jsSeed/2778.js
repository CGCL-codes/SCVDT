function f0() {
    do {
    } while (false);
    return true;
}
if (!f0())
    throw new Error('Test failed');
