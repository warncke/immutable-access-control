'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - audit allow module', function () {

    var accessControl

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
        // create new instance
        accessControl = new ImmutableAccessControl({strict: false})
    })

    it('should audit allow access to module when no rules', function () {
        // check access
        assert.isTrue(accessControl.allowModule({
            method: 'bar',
            module: 'foo',
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'module')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [])
    })

    it('should audit deny access when denied for all modules', function () {
        // set rules
        accessControl.setRule(['all', 'module:0'])
        // check access
        assert.isFalse(accessControl.allowModule({
            method: 'bar',
            module: 'foo',
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'module')
        assert.strictEqual(audit.allow, false)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {allow: false, role: 'all', ruleType: 'global', rules: {all: 0}},
        ])
    })

    it('should audit allow access when denied for all modules but allowed for role', function () {
        // set rules
        accessControl.setRule(['all', 'module:0'])
        accessControl.setRule(['foo', 'module:1'])
        // check access
        assert.isTrue(accessControl.allowModule({
            method: 'bar',
            module: 'foo',
            session: { roles: ['foo'] },
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'module')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {allow: true, role: 'foo', ruleType: 'global', rules: {all: 0, foo: 1}},
        ])
    })

    it('should audit deny access for module', function () {
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
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'module')
        assert.strictEqual(audit.allow, false)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {allow: true, role: 'foo', ruleType: 'global', rules: {all: 0, foo: 1}},
            {allow: false, role: 'all', ruleType: 'module', rules: {all: 0}},
        ])
    })

    it('should audit allow access for method', function () {
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
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'module')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {allow: true, role: 'foo', ruleType: 'global', rules: {all: 0, foo: 1}},
            {allow: false, role: 'all', ruleType: 'module', rules: {all: 0}},
            {allow: true, role: 'foo', ruleType: 'method', rules: {foo: 1}},
        ])
    })

})