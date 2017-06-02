'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - set rule', function () {

    var accessControl

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
        // create new instance
        accessControl = new ImmutableAccessControl()
    })

    it('should throw error on invalid input', function () {
        
        // set invalid rules
        assert.throws(function () {
            accessControl.setRule({})
        })
    })

    it('should throw error on missing roles', function () {
        // set invalid rules
        assert.throws(function () {
            accessControl.setRule(['model:0'])
        })
    })

    it('should throw error on invalid rule', function () {
        // set invalid rules
        assert.throws(function () {
            accessControl.setRule(['admin', null])
        })
    })

    it('should throw error on invalid allow', function () {
        // set invalid rules
        assert.throws(function () {
            accessControl.setRule(['admin', 'model:false'])
        })
    })

    it('should throw error on invalid resource type', function () {
        // set invalid rules
        assert.throws(function () {
            accessControl.setRule(['admin', 'foo:1'])
        })
    })

    it('should throw error setting deny rule on role other than all', function () {
        // set invalid rules
        assert.throws(function () {
            accessControl.setRule(['foo', 'model:0'])
        })
        // set invalid rules
        assert.throws(function () {
            accessControl.setRule(['all', 'foo', 'model:0'])
        })
    })
})