function f0() {
    return Reflect.has({ qux: 987 }, 'qux');
}
if (!f0())
    throw new Error('Test failed');
