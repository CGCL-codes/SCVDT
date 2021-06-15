if (!this.hasOwnProperty('TypedObject'))
    throw new Error();
var v0 = TypedObject.uint8.array(10);
var v1 = new v0();
v1.forEach(function (val, i) {
    assertEq(arguments[5], v1);
});
