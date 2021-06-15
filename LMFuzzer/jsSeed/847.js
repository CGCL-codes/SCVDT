if (!this.hasOwnProperty('TypedObject'))
    throw new TypeError();
var v0 = TypedObject.float32.array(3);
var v1 = v0.array(3);
var v2 = new v1();
v2[/\u00ee[]/] = new v0([
    1,
    0,
    0
]);
