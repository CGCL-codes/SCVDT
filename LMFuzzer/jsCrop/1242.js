function f0() {
    return {
        'foo bar'() {
            return 4;
        }
    }['foo bar']() === 4;
}
if (!f0())
    throw new Error('Test failed');
