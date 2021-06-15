load("fcfbc86708bc3a4062c2091a062e13b6.js");
load("faa81dc98fc13338aca921d45eebae79.js");
// Copyright 2009 the Sputnik authors.  All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

/**
 * Function argument that isn't provided has a value of undefined
 *
 * @path ch08/8.1/S8.1_A5.js
 * @description Call function without provided argument
 */

///////////////////////////////////////
//
function test(arg) {
// Check and make sure that arg is not undefined
	if (typeof(arg) !== "undefined") {
    $ERROR('#1: Function argument that isn\'t provided has a value of undefined. Actual: ' + (typeof(arg)));
  }
}

test();
//
////////////////////////////////////////

