'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - set rule module', function () {

    var accessControl

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
        // create new instance
        accessControl = new ImmutableAccessControl()
    })

    it('should set blanket rule for all modules', function () {
        // set rule
        accessControl.setRule(['foo', 'bar', 'module:1'])
        // check rules
        assert.deepEqual(accessControl.rules.module, { allow: { foo: 1, bar: 1 } })
    })

    it('should set blanket rule for single module', function () {
        // set rule
        accessControl.setRule(['foo', 'module:bar:1'])
        // check rules
        assert.deepEqual(accessControl.rules.module.module, { bar: { allow: { foo: 1 } } })
    })

    it('should set rule for method', function () {
        // set rule
        accessControl.setRule(['foo', 'module:bar:bam:1'])
        // check rules
        assert.deepEqual(accessControl.rules.module.module, {
            bar: { method: { bam: { allow: { foo: 1 } } } }
        }) 
    })

    it('should set multiple rules', function () {
        // set rules
        accessControl.setRule(['foo', 'bar', 'module:1'])
        accessControl.setRule(['foo', 'module:bar:1'])
        accessControl.setRule(['foo', 'module:bar:bam:1'])
        accessControl.setRule(['bar', 'module:bar:bam:1'])
        accessControl.setRule(['foo', 'module:bar:baz:1'])
        accessControl.setRule(['bar', 'module:bar:baz:1'])
        // check rules
        assert.deepEqual(accessControl.rules.module, { 
            allow: {foo: 1, bar: 1},  
            module: {
                bar: {
                    allow: {foo: 1},  
                    method: {
                        bam: {allow: {bar: 1, foo: 1}},  
                        baz: {allow: {bar: 1, foo: 1}},   
                    },
                },
            },
        })
    })

    it('should throw error on invalid rule', function () {
        // set invalid rule
        assert.throws(function () {
            accessControl.setRule(['foo', 'module:bar:bam:bam:1'])
        })
    })

})
