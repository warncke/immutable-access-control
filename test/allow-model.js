'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - allow model', function () {

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
    })

    it('should deny access to model when all access denied', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'model:0'])
        // check access
        assert.isFalse(accessControl.allowModel({
            action: 'create',
            model: 'foo',
        }))
    })

    it('should allow access to model with correct role', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['foo', 'model:1'])
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'create',
            model: 'foo',
            session: { roles: ['all', 'foo'] },
        }))
    })

    it('should allow access on model specific rule', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['foo', 'model:foo:1'])
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'create',
            model: 'foo',
            session: { roles: ['all', 'foo'] },
        }))
    })

    it('should allow access on action specific rule', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['foo', 'model:foo:create:1'])
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'create',
            model: 'foo',
            session: { roles: ['all', 'foo'] },
        }))
    })

    it.skip('should allow access on scope specific rule', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['foo', 'model:foo:delete:own:1'])
        // check access
        assert.isTrue(accessControl.allowModel({
            accessId: 'foo',
            action: 'delete',
            model: 'foo',
            session: { accountId: 'foo', roles: ['all', 'foo'] },
        }))
    })

})
