Function.prototype.indicator = 1;
if (String.indicator !== 1) {
    $ERROR('#1: Function.prototype.indicator = 1; String.indicator === 1. Actual: String.indicator ===' + String.indicator);
}
