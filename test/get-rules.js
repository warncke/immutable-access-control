'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - get rules', function () {

    var accessControl

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
        // create new instance
        accessControl = new ImmutableAccessControl()
    })

    it('should return all rules when no resource type set', function () {
        // set rules
        accessControl.setRule(['all', 'model:0'])
        // get rules
        var rules = accessControl.getRules()
        // check rules
        assert.deepEqual(rules, {model:{allow:{all: 0}}})
    })

    it('should return resource rules when resource type set', function () {
        // set rules
        accessControl.setRule(['all', 'model:0'])
        // get rules
        var rules = accessControl.getRules('model')
        // check rules
        assert.deepEqual(rules, {allow:{all: 0}})
    })

    it('should return undefined if resource type not found', function () {
        // set rules
        accessControl.setRule(['all', 'model:0'])
        // get rules
        var rules = accessControl.getRules('foo')
        // check rules
        assert.isUndefined(rules)
    })

    it('should set id when get rules called', function () {
        // check that id is undefined
        assert.isUndefined(accessControl.id)
        // set rules
        accessControl.setRule(['all', 'model:0'])
        // get rules
        var rules = accessControl.getRules('foo')
        // check that id is defined
        assert.isDefined(accessControl.id)
    })

})
