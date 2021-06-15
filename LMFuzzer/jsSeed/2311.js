v0 = 1;
if (this.x !== 1) {
    $ERROR('#1: variable x is a property of global object');
}
if (delete this.x !== true) {
    $ERROR('#2: variable x has property attribute DontDelete');
}
