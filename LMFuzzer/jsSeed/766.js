function f0() {
    function f1() {
    }
    ;
    return f1.bind({}).name === 'bound foo' && function () {
    }.bind({}).name === 'bound ';
}
if (!f0())
    throw new Error('Test failed');
