v0 = v1;
v1 = function () {
    this.hello = 'yay';
};
var v2 = new v1();
WScript.Echo(v2.hello);
var v3 = { hello2: 'yay2' };
WScript.Echo(v3.hello);
WScript.Echo(v3.hello2);
