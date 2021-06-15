function f0() {
    var v0 = new RegExp('\\w', 'y');
    v0.exec('xy');
    return v0.exec('xy')[0] === 'y';
}
if (!f0())
    throw new Error('Test failed');
