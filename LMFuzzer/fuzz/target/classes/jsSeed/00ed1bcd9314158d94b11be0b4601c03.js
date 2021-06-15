load("fcfbc86708bc3a4062c2091a062e13b6.js");
load("faa81dc98fc13338aca921d45eebae79.js");
// Copyright 2009 the Sputnik authors.  All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

/**
 * Literal :: BooleanLiteral
 *
 * @path ch07/7.8/7.8.2/S7.8.2_A1_T1.js
 * @description BooleanLiteral :: true
 */

//CHECK#1
if (Boolean(true) !== true) {
  $ERROR('#1: Boolean(true) === true. Actual: Boolean(true) === ' + (Boolean(true)));
} 

