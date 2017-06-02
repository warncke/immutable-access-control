'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - get roles', function () {

    var accessControl

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
        // create new instance
        accessControl = new ImmutableAccessControl()
    })

    it('should return roles from session if set', function () {
        // get roles
        var roles = accessControl.getRoles({roles: ['foo', 'bar']})
        // check roles
        assert.deepEqual(roles, ['foo', 'bar'])
    })

    it('should return default roles if no session', function () {
        // get roles
        var roles = accessControl.getRoles()
        // check roles
        assert.deepEqual(roles, ['all', 'anonymous'])
    })

    it('should return default roles if session not object', function () {
        // get roles
        var roles = accessControl.getRoles([])
        // check roles
        assert.deepEqual(roles, ['all', 'anonymous'])
    })

    it('should return default roles if session roles not array', function () {
        // get roles
        var roles = accessControl.getRoles({roles: {}})
        // check roles
        assert.deepEqual(roles, ['all', 'anonymous'])
    })

    it('should return authenticated role if session has accountId but no roles', function () {
        // get roles
        var roles = accessControl.getRoles({accountId: 'foo'})
        // check roles
        assert.deepEqual(roles, ['all', 'authenticated'])
    })

})
