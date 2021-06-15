function f0() {
    return Object.getOwnPropertyDescriptor('a', 'foo') === undefined;
}
if (!f0())
    throw new Error('Test failed');
