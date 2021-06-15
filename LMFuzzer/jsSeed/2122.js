function f0() {
    return JSON.stringify(new Proxy(['foo'], {})) === '["foo"]';
}
if (!f0())
    throw new Error('Test failed');
