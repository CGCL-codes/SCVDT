function f0() {
    return Reflect.get({ qux: 987 }, 'qux') === 987;
}
if (!f0())
    throw new Error('Test failed');
