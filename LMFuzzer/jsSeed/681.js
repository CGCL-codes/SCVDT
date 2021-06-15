var v0 = new Error('msg1');
if (!Error.prototype.isPrototypeOf(v0)) {
    $ERROR('#1: Error.prototype.isPrototypeOf(err1) return true. Actual: ' + Error.prototype.isPrototypeOf(v0));
}
