'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - allow module', function () {

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
    })

    it('should allow access to module when no rules', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // check access
        assert.isTrue(accessControl.allowModule({
            method: 'bar',
            module: 'foo',
        }))
    })

    it('should deny access when denied for all modules', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rules
        accessControl.setRule(['all', 'module:0'])
        // check access
        assert.isFalse(accessControl.allowModule({
            method: 'bar',
            module: 'foo',
        }))
    })

    it('should allow access when denied for all modules but allowed for role', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rules
        accessControl.setRule(['all', 'module:0'])
        accessControl.setRule(['foo', 'module:1'])
        // check access
        assert.isTrue(accessControl.allowModule({
            method: 'bar',
            module: 'foo',
            session: { roles: ['foo'] },
        }))
    })

    it('should deny access for module', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rules
        accessControl.setRule(['all', 'module:0'])
        accessControl.setRule(['foo', 'module:1'])
        accessControl.setRule(['all', 'module:foo:0'])
        // check access
        assert.isFalse(accessControl.allowModule({
            method: 'bar',
            module: 'foo',
            session: { roles: ['foo'] },
        }))
    })

    it('should allow access for method', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rules
        accessControl.setRule(['all', 'module:0'])
        accessControl.setRule(['foo', 'module:1'])
        accessControl.setRule(['all', 'module:foo:0'])
        accessControl.setRule(['foo', 'module:foo:bar:1'])
        // check access
        assert.isTrue(accessControl.allowModule({
            method: 'bar',
            module: 'foo',
            session: { roles: ['foo'] },
        }))
    })

    it('should throw error on missing module in strict model', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // check access without module name - should throw
        assert.throws(function () {
            accessControl.allowModule({
                method: 'bar',
                session: { roles: ['foo'], sessionId: 'foo' },
            })
        });
    })

    it('should throw error on missing method in strict mode', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()
        // check access without module name - should throw
        assert.throws(function () {
            accessControl.allowModule({
                module: 'foo',
                session: { roles: ['foo'], sessionId: 'foo' },
            })
        });
    })

    it('should throw error when missing sessionId in strict mode', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl()

        assert.throws(function () {
            accessControl.allowModule({
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
            accessControl.allowModule({
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
            accessControl.allowModule({
                model: 'foo',
                action: 'create',
            })
        })
    })

})