'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control', function () {

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
    })

    it('should instantiate new access control instance', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // validate instance
        assert.isObject(accessControl)
        assert.instanceOf(accessControl, ImmutableAccessControl)
        // check for required methods
        assert.isFunction(accessControl.setRule)
        assert.isFunction(accessControl.setRules)
    })

    it('should create global singleton instance', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // set rules
        accessControl.setRules([
            ['all', '*:0']
        ])
        // create new instance - should be same
        accessControl = new ImmutableAccessControl()
        // check that values set
        assert.deepEqual(accessControl.rules, { '*': { allow: { all: 0 } } })
    })

})