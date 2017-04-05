'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - get roles', function () {

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
    })

    it('should return roles from session if set', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // get roles
        var roles = accessControl.getRoles({roles: ['foo', 'bar']})
        // check roles
        assert.deepEqual(roles, ['foo', 'bar'])
    })

    it('should return default roles if no session', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // get roles
        var roles = accessControl.getRoles()
        // check roles
        assert.deepEqual(roles, ['all', 'anonymous'])
    })

    it('should return default roles if session not object', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // get roles
        var roles = accessControl.getRoles([])
        // check roles
        assert.deepEqual(roles, ['all', 'anonymous'])
    })

    it('should return default roles if session roles not array', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // get roles
        var roles = accessControl.getRoles({roles: {}})
        // check roles
        assert.deepEqual(roles, ['all', 'anonymous'])
    })

    it('should return authenticated role if session has accountId but no roles', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // get roles
        var roles = accessControl.getRoles({accountId: 'foo'})
        // check roles
        assert.deepEqual(roles, ['all', 'authenticated'])
    })

})
