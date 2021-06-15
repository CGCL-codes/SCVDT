assert.sameValue(Date.UTC.name, 'UTC');
verifyNotEnumerable(Date.UTC, 'name');
verifyNotWritable(Date.UTC, 'name');
verifyConfigurable(Date.UTC, 'name');
