function f0() {
    function f1() {
        let v0 = 'a';
        function f2() {
        }
        v0;
    }
    f1();
}
;
f0();
WScript.Attach(f0);
WScript.Echo('Pass');
