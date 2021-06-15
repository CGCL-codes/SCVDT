if (Array.prototype.isPrototypeOf(new Array()) !== true) {
    $ERROR('#1: Array.prototype.isPrototypeOf(new Array()) === true. Actual: ' + Array.prototype.isPrototypeOf(new Array()));
}
