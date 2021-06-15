function f0() {
    return arguments.length;
}
;
if (f0(1, 2, 3) !== 3) {
    $ERROR('#1: function __mFunc(){return arguments.length;}; __mFunc(1,2,3) === 3. Actual: ' + f0(1, 2, 3));
}
