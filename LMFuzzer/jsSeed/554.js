Function.prototype.indicator = 1;
if (Function.indicator != 1) {
    $ERROR('#1: the value of the internal [[Prototype]] property of the Function constructor is the Function prototype object.');
}
