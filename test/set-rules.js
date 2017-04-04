'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - set rules', function () {

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
    })

    it('should throw error on invalid input', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // set invalid rules
        assert.throws(function () {
            accessControl.setRules({})
        })

    })
})