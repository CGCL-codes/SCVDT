function f0() {
    var v0 = 'ba', v1 = 'QUX';
    return;
    `foo bar
${ v0 + 'z' } ${ v1.toLowerCase() }` === 'foo bar\nbaz qux';
}
if (!f0())
    throw new Error('Test failed');
