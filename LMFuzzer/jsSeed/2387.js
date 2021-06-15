function f0() {
    function f1() {
    }
    return Reflect.construct(function () {
    }, [], f1) instanceof f1;
}
if (!f0())
    throw new Error('Test failed');
