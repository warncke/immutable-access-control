'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - audit allow model', function () {

    var accessControl

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
        // create new instance
        accessControl = new ImmutableAccessControl({strict: false})
    })

    it('should audit allow access to model when no rules', function () {
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'create',
            model: 'foo',
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true}
        ])
    })

    it('should audit deny access to model when all access denied', function () {
        // set rule
        accessControl.setRule(['all', 'model:0'])
        // check access
        assert.isFalse(accessControl.allowModel({
            action: 'create',
            model: 'foo',
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, false)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {ruleType: 'global', rules: { all: 0 }, role: 'all', allow: false},
        ])
    })

    it('should audit allow access to model with correct role', function () {
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['foo', 'model:1'])
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'create',
            model: 'foo',
            session: { roles: ['all', 'foo'] },
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {ruleType: 'global', rules: { all: 0, foo: 1 }, role: 'foo', allow: true},
        ])
    })

    it('should audit allow access on model specific rule', function () {
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['foo', 'model:foo:1'])
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'create',
            model: 'foo',
            session: { roles: ['all', 'foo'] },
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {ruleType: 'global', rules: { all: 0 }, role: 'all', allow: false},
            {ruleType: 'model', rules: { foo: 1 }, role: 'foo', allow: true},
        ])
    })

    it('should audit allow access on action specific rule', function () {
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['foo', 'model:foo:create:1'])
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'create',
            model: 'foo',
            session: { roles: ['all', 'foo'] },
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {ruleType: 'global', rules: { all: 0 }, role: 'all', allow: false},
            {ruleType: 'action', rules: { foo: 1 }, role: 'foo', allow: true},
        ])
    })

    it('should audit deny access for any on action specific rule', function () {
        // set rule
        accessControl.setRule(['all', 'model:foo:delete:any:0'])
        // check access
        assert.isFalse(accessControl.allowModel({
            accessId: 'foo',
            action: 'delete',
            model: 'foo',
            session: { accessId: 'foo', accountId: 'foo', roles: ['all', 'foo'] },
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, false)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {allow: false, role: 'all', ruleType: 'action', rules: { all: 0 }, allowScope: 'own', ruleScope: 'any'},
        ])
    })

    it('should audit deny access for own on action specific rule', function () {
        // set rule
        accessControl.setRule(['all', 'model:foo:delete:own:0'])
        // check access
        assert.isFalse(accessControl.allowModel({
            accessId: 'foo',
            action: 'delete',
            model: 'foo',
            session: { accessId: 'foo', accountId: 'foo', roles: ['all', 'foo'] },
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, false)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {allow: false, role: 'all', ruleType: 'action', rules: { all: 0 }, allowScope: 'own', ruleScope: 'own'},
        ])
    })

    it('should audit allow access for own while denied for any on action specific rule', function () {
        // set rule
        accessControl.setRule(['all', 'model:foo:delete:any:0'])
        accessControl.setRule(['all', 'model:foo:delete:own:1'])
        // check access
        assert.isTrue(accessControl.allowModel({
            accessId: 'foo',
            action: 'delete',
            model: 'foo',
            session: { accessId: 'foo', accountId: 'foo', roles: ['all', 'foo'] },
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {allow: false, role: 'all', ruleType: 'action', rules: { all: 0 }, allowScope: 'own', ruleScope: 'any'},
            {allow: true, role: 'all', ruleType: 'action', rules: { all: 1 }, allowScope: 'own', ruleScope: 'own'},
        ])
    })

    it('should audit allow access on deleted state with specific rule', function () {
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
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: true, allow: false},
            {allow: false, role: 'all', ruleType: 'global', rules: { all: 0 }},
            {allow: true, role: 'foo', ruleType: 'state', rules: { foo: 1 }, allowScope: 'any', ruleScope: 'any', state: 'deleted'},
        ])
    })

    it('should audit deny access unless all states allowed', function () {
        // set rule
        accessControl.setRule(['all', 'model:foo:read:bar:any:0'])
        accessControl.setRule(['foo', 'model:foo:read:foo:any:1'])
        // check access
        assert.isFalse(accessControl.allowModel({
            action: 'read',
            model: 'foo',
            scope: 'any',
            session: { roles: ['all', 'foo'] },
            states: ['foo', 'bar']
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, false)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {allow: true, role: 'foo', ruleType: 'state', rules: { foo: 1 }, allowScope: 'any', ruleScope: 'any', state: 'foo'},
            {allow: false, role: 'all', ruleType: 'state', rules: { all: 0 }, allowScope: 'any', ruleScope: 'any', state: 'bar'},
        ])
    })

    it('should audit deny access unless all states allowed - state order variant', function () {
        // set rule
        accessControl.setRule(['all', 'model:foo:read:bar:any:0'])
        accessControl.setRule(['foo', 'model:foo:read:foo:any:1'])
        // check access
        assert.isFalse(accessControl.allowModel({
            action: 'read',
            model: 'foo',
            scope: 'any',
            session: { roles: ['all', 'foo'] },
            // because all states must be allowed evaluation short-circuits on
            // the first deny rule so the order of states can change audit
            states: ['bar', 'foo']
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, false)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {allow: false, role: 'all', ruleType: 'state', rules: { all: 0 }, allowScope: 'any', ruleScope: 'any', state: 'bar'},
        ])
    })

    it('should audit apply allow state rule on any scope to own scope', function () {
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
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: true, allow: false},
            {allow: false, role: 'all', ruleType: 'global', rules: { all: 0 }},
            {allow: true, role: 'foo', ruleType: 'state', rules: { foo: 1 }, allowScope: 'own', ruleScope: 'any', state: 'deleted'},
        ])
    })

    it('should audit deny access on deleted state by default', function () {
        // check access
        assert.isFalse(accessControl.allowModel({
            action: 'read',
            model: 'foo',
            scope: 'any',
            session: { roles: ['all', 'foo'] },
            states: ['deleted']
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, false)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: true, allow: false},
        ])
    })

    it('should audit allow access on scope specific rule with accountId as accessId', function () {
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['foo', 'model:foo:delete:own:1'])
        // check access
        assert.isTrue(accessControl.allowModel({
            accessId: 'foo',
            action: 'delete',
            model: 'foo',
            session: { accessId: 'foo', accountId: 'foo', roles: ['all', 'foo'] },
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {allow: false, role: 'all', ruleType: 'global', rules: { all: 0 }},
            {allow: true, role: 'foo', ruleType: 'action', rules: { foo: 1 }, allowScope: 'own', ruleScope: 'own'},
        ])
    })

    it('should audit allow access on scope specific rule with custom accessId', function () {
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
            session: { accessId: 'foo', fooId: 'foo', roles: ['all', 'foo'] },
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {allow: false, role: 'all', ruleType: 'global', rules: { all: 0 }},
            {allow: true, role: 'foo', ruleType: 'action', rules: { foo: 1 }, allowScope: 'own', ruleScope: 'own'},
        ])
    })

    it('should audit allow access on scope specific rule with scope:own', function () {
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
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {allow: false, role: 'all', ruleType: 'global', rules: { all: 0 }},
            {allow: true, role: 'foo', ruleType: 'action', rules: { foo: 1 }, allowScope: 'own', ruleScope: 'own'},
        ])
    })

    it('should audit deny access on own scope rule with scope:any', function () {
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
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, false)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {allow: false, role: 'all', ruleType: 'global', rules: { all: 0 }},
        ])
    })

    it('should audit not deny access on any scope if own scope denied', function () {
        // set rule
        accessControl.setRule(['all', 'model:foo:delete:own:0'])
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'delete',
            model: 'foo',
            scope: 'any',
            session: { roles: ['all', 'foo'] },
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
        ])
    })

    it('should audit allow access on scope:own when scope:any allowed', function () {
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
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'model')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {allow: false, role: 'all', ruleType: 'global', rules: { all: 0 }},
            {allow: true, role: 'foo', ruleType: 'action', rules: { foo: 1 }, allowScope: 'own', ruleScope: 'any'},
        ])
    })

})