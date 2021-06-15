if (+0.1 !== 0.1) {
    $ERROR('#1: +0.1 === 0.1. Actual: ' + +0.1);
}
if (+new Number(-1.1) !== -1.1) {
    $ERROR('#2: +new Number(-1.1) === -1.1. Actual: ' + +new Number(-1.1));
}
