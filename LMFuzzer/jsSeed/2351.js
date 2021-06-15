function f0(array) {
    return array[0];
}
function f1(a) {
    return arguments;
}
for (var v0 = 0; v0 < 10; v0++) {
    f0(f1(1));
}
f0('123');
