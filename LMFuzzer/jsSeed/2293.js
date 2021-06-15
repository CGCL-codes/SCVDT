Function.prototype.indicator = 1;
if (RegExp.indicator !== 1) {
    $ERROR('#1: Function.prototype.indicator = 1; RegExp.indicator === 1. Actual: ' + RegExp.indicator);
}
