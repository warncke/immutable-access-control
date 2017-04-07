'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - allow model', function () {

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
    })

    it('should allow access to model when no rules', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'create',
            model: 'foo',
        }))
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

    it('should allow access on deleted state with specific rule', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['foo', 'model:foo:read:deleted:any:1'])
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'read',
            model: 'foo',
            scope: 'any',
            session: { roles: ['all', 'foo'] },
            states: ['deleted']
        }))
    })

    it('should deny access unless all states allowed', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'model:foo:read:bar:any:0'])
        accessControl.setRule(['foo', 'model:foo:read:foo:any:1'])
        // check access
        assert.isFalse(accessControl.allowModel({
            action: 'read',
            model: 'foo',
            scope: 'any',
            session: { roles: ['all', 'foo'] },
            states: ['bar', 'foo']
        }))
    })

    it('should apply allow state rule on any scope to own scope', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['foo', 'model:foo:read:deleted:any:1'])
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'read',
            model: 'foo',
            scope: 'own',
            session: { roles: ['all', 'foo'] },
            states: ['deleted']
        }))
    })

    it('should deny access on deleted state by default', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // check access
        assert.isFalse(accessControl.allowModel({
            action: 'read',
            model: 'foo',
            scope: 'any',
            session: { roles: ['all', 'foo'] },
            states: ['deleted']
        }))
    })

    it('should allow access on scope specific rule with accountId as accessId', function () {
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

    it('should allow access on scope specific rule with custom accessId', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set custom access id
        accessControl.setAccessIdName('foo', 'fooId')
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['foo', 'model:foo:delete:own:1'])
        // check access
        assert.isTrue(accessControl.allowModel({
            accessId: 'foo',
            action: 'delete',
            model: 'foo',
            session: { fooId: 'foo', roles: ['all', 'foo'] },
        }))
    })

    it('should allow access on scope specific rule with scope:own', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['foo', 'model:foo:delete:own:1'])
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'delete',
            model: 'foo',
            scope: 'own',
            session: { roles: ['all', 'foo'] },
        }))
    })

    it('should deny access on own scope rule with scope:any', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['foo', 'model:foo:delete:own:1'])
        // check access
        assert.isFalse(accessControl.allowModel({
            action: 'delete',
            model: 'foo',
            scope: 'any',
            session: { roles: ['all', 'foo'] },
        }))
    })

    it('should not deny access on any scope if own scope denied', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'model:foo:delete:own:0'])
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'delete',
            model: 'foo',
            scope: 'any',
            session: { roles: ['all', 'foo'] },
        }))
    })

    it('should allow access on scope:own when scope:any allowed', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['foo', 'model:foo:delete:any:1'])
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'delete',
            model: 'foo',
            scope: 'own',
            session: { roles: ['all', 'foo'] },
        }))
    })

    it('should throw error when missing model in strict mode', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()

        assert.throws(function () {
            accessControl.allowModel({
                action: 'create',
                session: { roles: ['all'], sessionId: 'foo' },
            })
        })
    })

    it('should throw error when missing action in strict mode', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()

        assert.throws(function () {
            accessControl.allowModel({
                model: 'foo',
                session: { roles: ['all'], sessionId: 'foo' },
            })
        })
    })

    it('should throw error when missing sessionId in strict mode', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()

        assert.throws(function () {
            accessControl.allowModel({
                model: 'foo',
                action: 'create',
                session: { roles: ['all'] },
            })
        })
    })

    it('should throw error when missing roles in strict mode', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()

        assert.throws(function () {
            accessControl.allowModel({
                model: 'foo',
                action: 'create',
                session: { sessionId: 'foo' },
            })
        })
    })

    it('should throw error when missing session in strict mode', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()

        assert.throws(function () {
            accessControl.allowModel({
                model: 'foo',
                action: 'create',
            })
        })
    })

    it('should not throw error if no scope on create in strict mode', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()

        assert.doesNotThrow(function () {
            accessControl.allowModel({
                model: 'foo',
                action: 'create',
                session: { roles: ['all'], sessionId: 'foo' },
            })
        })
    })

    it('should throw error if no scope on action other than create in strict mode', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()

        assert.throws(function () {
            accessControl.allowModel({
                model: 'foo',
                action: 'foo',
                session: { roles: ['all'], sessionId: 'foo' },
            })
        })
    })

    it('should throw not throw error with scope in strict mode', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()

        assert.doesNotThrow(function () {
            accessControl.allowModel({
                model: 'foo',
                action: 'foo',
                scope: 'any',
                session: { roles: ['all'], sessionId: 'foo' },
            })
        })
    })

    it('should throw not throw error with accessId in strict mode', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()

        assert.doesNotThrow(function () {
            accessControl.allowModel({
                accessId: 'foo',
                model: 'foo',
                action: 'foo',
                session: { roles: ['all'], sessionId: 'foo' },
            })
        })
    })

})
