function f0() {
    delete arguments;
    return arguments;
}
if (typeof f0('A', 'B', 1, 2) !== 'object') {
    $ERROR('#1: arguments property has attribute { DontDelete }');
}
