function f0(a) {
    delete a;
    return a;
}
if (f0(1) !== 1)
    $ERROR('#1: Function parameter was deleted');
