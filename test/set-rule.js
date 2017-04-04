'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - set rule', function () {

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
    })

    it('should throw error on invalid input', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // set invalid rules
        assert.throws(function () {
            accessControl.setRule({})
        })
    })

    it('should throw error on missing roles', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // set invalid rules
        assert.throws(function () {
            accessControl.setRule(['*:0'])
        })
    })

    it('should throw error on invalid rule', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // set invalid rules
        assert.throws(function () {
            accessControl.setRule(['admin', null])
        })
    })

    it('should throw error on invalid allow', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // set invalid rules
        assert.throws(function () {
            accessControl.setRule(['admin', '*:false'])
        })
    })

    it('should throw error on invalid resource type', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // set invalid rules
        assert.throws(function () {
            accessControl.setRule(['admin', 'foo:1'])
        })
    })

    it('should throw error setting deny rule on role other than all', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // set invalid rules
        assert.throws(function () {
            accessControl.setRule(['foo', '*:0'])
        })
        // set invalid rules
        assert.throws(function () {
            accessControl.setRule(['all', 'foo', '*:0'])
        })
    })
})