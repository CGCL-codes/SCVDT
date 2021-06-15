function f0() {
}
;
var v0 = new f0();
if (delete MyObjectNotVar !== true) {
    $ERROR('#1: function MyFunction(){}; var MyObjectNotVar = new MyFunction(); delete MyObjectNotVar === true');
}
