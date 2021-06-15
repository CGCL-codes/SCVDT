v0 = 'ecma_2';
var v1 = f0();
function f0() {
    return -new Date(2000, 1, 1).getTimezoneOffset() / 60;
}
