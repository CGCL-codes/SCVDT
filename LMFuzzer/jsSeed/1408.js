if (Array.prototype.isPrototypeOf(new Array(0)) !== true) {
    $ERROR('#1: Array.prototype.isPrototypeOf(new Array(0)) === true. Actual: ' + Array.prototype.isPrototypeOf(new Array(0)));
}
