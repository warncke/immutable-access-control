'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - set rule any', function () {

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
    })

    it('should set global rule that applies to any resource', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // set rule
        accessControl.setRule(['all', '*:0'])
        // check rule
        assert.deepEqual(accessControl.rules, { '*': { allow: { all: 0 } } })
    })

    it('should throw error on invalid input', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // set invalid rules
        assert.throws(function () {
            accessControl.setRule(['all', '*:foo:0'])
        })
    })

})