function f0(msg) {
    print(msg);
}
function f1() {
    if (!arguments[0])
        f0('Test262:AsyncTestComplete');
    else
        f0('Error: ' + arguments[0]);
}
