'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - audit allow model scope', function () {

    var accessControl

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
        // create new instance
        accessControl = new ImmutableAccessControl({strict: false})
    })

    it('should audit return any when any scope allowed', function () {
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['all', 'model:foo:1'])
        // get scope
        var scope = accessControl.allowModelScope({
            action: 'list',
            model: 'foo',
        })
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'modelScope')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.scope, 'any')
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {ruleType: 'global', rules: { all: 0 }, role: 'all', allow: false},
            {allow: true, role: 'all', ruleType: 'model', rules: {all: 1 }},
        ])
    })

    it('should audit return own when own scope allowed', function () {
        // set rule
        accessControl.setRule(['all', 'model:0'])
        accessControl.setRule(['all', 'model:foo:list:own:1'])
        // get scope
        var scope = accessControl.allowModelScope({
            action: 'list',
            model: 'foo',
        })
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'modelScope')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.scope, 'own')
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {ruleType: 'global', rules: { all: 0 }, role: 'all', allow: false},
            {deleted: false, allow: true},
            {ruleType: 'global', rules: { all: 0 }, role: 'all', allow: false},
            {allow: true, role: 'all', ruleType: 'action', rules: { all: 1 }, allowScope: 'own', ruleScope: 'own' },
        ])
    })

    it('should audit return undefined when access denied', function () {
        // set rule
        accessControl.setRule(['all', 'model:0'])
        // get scope
        var scope = accessControl.allowModelScope({
            action: 'list',
            model: 'foo',
        })
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'modelScope')
        assert.strictEqual(audit.allow, false)
        assert.strictEqual(audit.scope, undefined)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {deleted: false, allow: true},
            {ruleType: 'global', rules: { all: 0 }, role: 'all', allow: false},
            {deleted: false, allow: true},
            {ruleType: 'global', rules: { all: 0 }, role: 'all', allow: false},
        ])
    })

})