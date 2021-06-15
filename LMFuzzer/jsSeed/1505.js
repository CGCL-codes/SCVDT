var v0 = Function.call(this, 'return this.planet;');
if (v0() !== undefined) {
    $ERROR('#1: ');
}
var v1 = 'mars';
if (v0() !== 'mars') {
    $ERROR('#2: ');
}
