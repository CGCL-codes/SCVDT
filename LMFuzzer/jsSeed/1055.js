Object.prototype.indicator = 1;
if (RegExp.prototype.indicator !== 1) {
    $ERROR('#1: Object.prototype.indicator = 1; RegExp.prototype.indicator === 1. Actual: ' + RegExp.prototype.indicator);
}
