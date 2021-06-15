if (this.x !== undefined) {
    $ERROR('#1: this.x === undefined. Actual: ' + this.x);
}
this.x++;
if (x === undefined) {
    $ERROR('#2: this.x; this.x++; x !== undefined');
}
