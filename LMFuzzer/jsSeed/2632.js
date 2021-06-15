if (!this.hasOwnProperty('TypedObject'))
    throw new Error();
var v0 = TypedObject.uint16.array(1073741823);
var v1 = new TypedObject.StructType({
    fst: v0,
    snd: v0
});
new v1();
