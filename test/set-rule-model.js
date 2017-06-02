'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - set rule model', function () {

    var accessControl

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
        // create new instance
        accessControl = new ImmutableAccessControl()
    })

    it('should set blanket rule for all models', function () {
        // set rule
        accessControl.setRule(['foo', 'bar', 'model:1'])
        // check rules
        assert.deepEqual(accessControl.rules.model, { allow: { foo: 1, bar: 1 } })
    })

    it('should set blanket rule for single model', function () {
        // set rule
        accessControl.setRule(['foo', 'model:bar:1'])
        // check rules
        assert.deepEqual(accessControl.rules.model.model, { bar: { allow: { foo: 1 } } })
    })

    it('should set rule for model create', function () {
        // set rule
        accessControl.setRule(['foo', 'model:bar:create:1'])
        // check rules
        assert.deepEqual(accessControl.rules.model.model, {
            bar: { action: { create: { allow: { foo: 1 } } } }
        })
    })

    it('should throw error on invalid create', function () {
        // set invalid rule
        assert.throws(function () {
            accessControl.setRule(['foo', 'model:bar:create:any:1'])
        })
    })

    it('should set rule to read own', function () {
        // set rule
        accessControl.setRule(['foo', 'model:bar:read:own:1'])
        // check rules
        assert.deepEqual(accessControl.rules.model.model, {
            bar: { action: { read: { own: { allow: { foo: 1 } } } } }
        })
    })

    it('should set rule to read own with action', function () {
        // set rule
        accessControl.setRule(['foo', 'model:bar:read:deleted:own:1'])
        // check rules
        assert.deepEqual(accessControl.rules.model.model, {
            bar: { action: { read: { state: { deleted: { own: { allow: { foo: 1 } } } } } } }
        })
    })

    it('should set multiple rules', function () {
        // set rules
        accessControl.setRule(['foo', 'bar', 'model:1'])
        accessControl.setRule(['foo', 'model:bar:1'])
        accessControl.setRule(['foo', 'model:bar:create:1'])
        accessControl.setRule(['foo', 'model:bar:read:own:1'])
        accessControl.setRule(['foo', 'model:bar:foo:any:1'])
        accessControl.setRule(['bar', 'model:bar:read:own:1'])
        accessControl.setRule(['bar', 'model:bar:foo:any:1'])
        // check rules
        assert.deepEqual(accessControl.rules.model, { 
            allow: {foo: 1, bar: 1},  
            model: {
                bar: {
                    allow: {foo: 1},
                    action: {
                        create: {allow: {foo: 1}},
                        read: {own: {allow: {foo: 1, bar: 1}}},
                        foo: {any: {allow: {foo: 1, bar: 1}}},
                    },
                },
            },
        })
    })

    it('should throw error on read rule with missing scope', function () {
        // set invalid rule
        assert.throws(function () {
            accessControl.setRule(['foo', 'model:bar:read:1'])
        })
    })

    it('should throw error on read rule with invalid scope', function () {
        // set invalid rule
        assert.throws(function () {
            accessControl.setRule(['foo', 'model:bar:read:ours:1'])
        })
    })

})
