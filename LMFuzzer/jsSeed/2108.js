function f0() {
    return delete arguments;
}
if (f0('A', 'B', 1, 2)) {
    $ERROR('#1: arguments property has attribute { DontDelete }');
}
