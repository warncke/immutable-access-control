'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - set rule route', function () {

    var accessControl

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
        // create new instance
        accessControl = new ImmutableAccessControl()
    })

    it('should set blanket rule for all route', function () {
        // set rule
        accessControl.setRule(['foo', 'bar', 'route:1'])
        // check rules
        assert.deepEqual(accessControl.rules.route, { allow: { foo: 1, bar: 1 } })
    })

    it('should set blanket rule for specific route', function () {
        // set rule
        accessControl.setRule(['foo', 'route:/bar:1'])
        // check rules
        assert.deepEqual(accessControl.rules.route.path, { bar: { allow: { foo: 1 } } })
    })

    it('should set rule for path and method', function () {
        // set rule
        accessControl.setRule(['foo', 'route:/bar:post:1'])
        // check rules
        assert.deepEqual(accessControl.rules.route.path, {
            bar: { method: { post : { allow: { foo: 1 } } } }
        })
    })

    it('should append index to trailing slash', function () {
        // set rule
        accessControl.setRule(['foo', 'route:/:post:1'])
        // check rules
        assert.deepEqual(accessControl.rules.route.path, {
            index: { method: { post : { allow: { foo: 1 } } } }
        })
    })

    it('should set multiple rules', function () {
        // set rules
        accessControl.setRule(['all', 'route:0'])
        accessControl.setRule(['foo', 'bar', 'route:1'])
        accessControl.setRule(['foo', 'route:/bar:post:1'])
        accessControl.setRule(['bar', 'route:/bar:post:1'])
        accessControl.setRule(['foo', 'route:/bar:put:1'])
        accessControl.setRule(['foo', 'route:/bar/foo:post:1'])
        accessControl.setRule(['bar', 'route:/bar/foo:post:1'])
        accessControl.setRule(['foo', 'route:/bar/foo/bam:1'])
        accessControl.setRule(['bar', 'route:/bar/foo/baz:1'])
        // check rules
        assert.deepEqual(accessControl.rules.route, {
            allow: {all: 0, foo: 1, bar: 1},
            path: {
                bar: {
                    method: {
                        post: {allow: {foo: 1, bar: 1}},
                        put: {allow: {foo: 1}},
                    },
                    path: {
                        foo: {
                            method: {
                                post: {allow: {foo: 1, bar: 1}}
                            },
                            path: {
                                bam: {allow: {foo: 1}},
                                baz: {allow: {bar: 1}}
                            }
                        }
                    }
                }
            }
        })
    })

    it('should throw error on path with no leading slash', function () {
        // set invalid rule
        assert.throws(function () {
            accessControl.setRule(['foo', 'route:foo:1'])
        })
    })

    it('should throw error on invalid clause', function () {
        // set invalid rule
        assert.throws(function () {
            accessControl.setRule(['foo', 'route:/foo:bar:bam:1'])
        })
    })

})
