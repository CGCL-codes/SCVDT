function f0(__arg) {
    return __arg;
}
;
if (typeof f0 !== 'function') {
    $ERROR('#1: unicode symbols in function name are allowed');
}
