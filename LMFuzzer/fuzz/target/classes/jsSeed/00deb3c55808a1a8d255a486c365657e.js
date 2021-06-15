load("bf4b12814bc95f34eeb130127d8438ab.js");
load("93fae755edd261212639eed30afa2ca4.js");
// Copyright (C) 2016 the V8 project authors. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.
/*---
esid: sec-date.prototype.togmtstring
es6id: B.2.4.3
es5id: B.2.6
description: Value of `Date.prototype.toGMTString`
info: >
    The function object that is the initial value of Date.prototype.toGMTString
    is the same function object that is the initial value of
    Date.prototype.toUTCString.
---*/

assert.sameValue(Date.prototype.toGMTString, Date.prototype.toUTCString);
