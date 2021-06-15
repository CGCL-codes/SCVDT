load("bf4b12814bc95f34eeb130127d8438ab.js");
load("93fae755edd261212639eed30afa2ca4.js");
// Copyright (c) 2012 Ecma International.  All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

/*---
es5id: 15.4.4.15-3-4
description: >
    Array.prototype.lastIndexOf - value of 'length' is a number (value
    is -0)
---*/

        var obj = { 0: true, length: -0 };

assert.sameValue(Array.prototype.lastIndexOf.call(obj, true), -1, 'Array.prototype.lastIndexOf.call(obj, true)');
