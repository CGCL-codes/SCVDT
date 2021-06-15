var v0 = new RegExp();
RegExp.prototype.indicator = 1;
if (v0.indicator !== 1) {
    $ERROR('#1: __re = new RegExp; RegExp.prototype.indicator = 1; __re.indicator === 1. Actual: ' + v0.indicator);
}
