load("bf4b12814bc95f34eeb130127d8438ab.js");
load("93fae755edd261212639eed30afa2ca4.js");
load("352fc54052b657308832185e13cd17c9.js");
// Copyright (C) 2016 the V8 project authors. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.
/*---
esid: sec-get-%typedarray%.prototype.bytelength
es6id: 22.2.3.2
description: |
  Throws a TypeError exception when `this` does not have a [[TypedArrayName]]
  internal slot
info: >
  22.2.3.2 get %TypedArray%.prototype.byteLength

  1. Let O be the this value.
  2. If Type(O) is not Object, throw a TypeError exception.
  3. If O does not have a [[TypedArrayName]] internal slot, throw a TypeError
  exception.
  ...
includes: [testTypedArray.js]
features: [DataView]
---*/

var TypedArrayPrototype = TypedArray.prototype;
var getter = Object.getOwnPropertyDescriptor(
  TypedArrayPrototype, "byteLength"
).get;

assert.throws(TypeError, function() {
  getter.call({});
});

assert.throws(TypeError, function() {
  getter.call([]);
});

var ab = new ArrayBuffer(8);
assert.throws(TypeError, function() {
  getter.call(ab);
});

var dv = new DataView(new ArrayBuffer(8), 0);
assert.throws(TypeError, function() {
  getter.call(dv);
});
