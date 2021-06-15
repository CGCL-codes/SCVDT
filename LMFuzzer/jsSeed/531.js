function f0() {
}
;
var v0 = new f0();
if (delete v0 !== false) {
    $ERROR('#1: function MyFunction(){}; var MyObjectVar = new MyFunction(); delete MyObjectVar === false');
}
