try {
    !Iterator(eval('      (function(){        (function a() {           new function(){            __iterator__ = a          }        }      )();       return this      })')());
} catch (e) {
}
