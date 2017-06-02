'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - allow model scope', function () {

    var accessControl

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
        // create new instance
        accessControl = new ImmutableAccessControl({strict: false})
    })

    it('should return any when any scope allowed', function () {
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['all', 'model:foo:1'])
        // get scope
        var scope = accessControl.allowModelScope({
            action: 'list',
            model: 'foo',
        })
        // check access
        assert.strictEqual(scope, 'any')
    })

    it('should return own when own scope allowed', function () {
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['all', 'model:foo:list:own:1'])
        // get scope
        var scope = accessControl.allowModelScope({
            action: 'list',
            model: 'foo',
        })
        // check access
        assert.strictEqual(scope, 'own')
    })

    it('should return undefined when access denied', function () {
        // set rule
        accessControl.setRule(['all', 'model:0'])
        // get scope
        var scope = accessControl.allowModelScope({
            action: 'list',
            model: 'foo',
        })
        // check access
        assert.isUndefined(scope)
    })

})