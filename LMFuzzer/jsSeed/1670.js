function f0(arg) {
    if (typeof arg !== 'undefined') {
        $ERROR('#1: Function argument that isn\'t provided has a value of undefined. Actual: ' + typeof arg);
    }
}
f0();
