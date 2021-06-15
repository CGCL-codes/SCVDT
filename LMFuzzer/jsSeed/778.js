var v0 = function () {
};
v0.prop = {
    value: 12,
    enumerable: true
};
var v1 = Object.create({}, v0);
assert(v1.hasOwnProperty('prop'), 'newObj.hasOwnProperty("prop") !== true');
