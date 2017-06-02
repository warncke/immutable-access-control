'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control', function () {

    var accessControl

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
        // create new instance
        accessControl = new ImmutableAccessControl()
    })

    it('should instantiate new access control instance', function () {
        // validate instance
        assert.isObject(accessControl)
        assert.instanceOf(accessControl, ImmutableAccessControl)
        // check for required methods
        assert.isFunction(accessControl.setRule)
        assert.isFunction(accessControl.setRules)
    })

    it('should create global singleton instance', function () {
        // set rules
        accessControl.setRules([
            ['all', 'model:0']
        ])
        // create new instance - should be same
        accessControl = new ImmutableAccessControl()
        // check that values set
        assert.deepEqual(accessControl.rules, { 'model': { allow: { all: 0 } } })
    })

})