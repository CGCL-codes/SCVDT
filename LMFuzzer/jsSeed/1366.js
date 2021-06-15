v0 = new Date(-2147483648, 42);
if (v0.toString() != 'Invalid Date')
    throw 'Expected "Invalid Date", but got :"' + v0 + '"';
