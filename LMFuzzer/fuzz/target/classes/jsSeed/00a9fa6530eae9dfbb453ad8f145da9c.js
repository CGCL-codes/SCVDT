load("bf4b12814bc95f34eeb130127d8438ab.js");
load("93fae755edd261212639eed30afa2ca4.js");
// Copyright 2009 the Sputnik authors.  All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

/*---
info: The Number prototype object has the property constructor
es5id: 15.7.4_A3.1
description: The test uses hasOwnProperty() method
---*/

//CHECK#1
if(Number.prototype.hasOwnProperty("constructor") !== true){
  $ERROR('#1: The Number prototype object has the property constructor');
}
