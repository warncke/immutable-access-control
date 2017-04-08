'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - allow route', function () {

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
    })

    it('should allow access to route when no rules', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // check access
        assert.isTrue(accessControl.allowRoute({
            method: 'get',
            path: '/',
        }))
    })

    it('should deny access to route when all routes denied', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'route:0'])
        // check access
        assert.isFalse(accessControl.allowRoute({
            method: 'get',
            path: '/',
        }))
    })

    it('should allow access to route when all routes denied and route allowed', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'route:0'])
        accessControl.setRule(['all', 'route:/:1'])
        // check access
        assert.isTrue(accessControl.allowRoute({
            method: 'get',
            path: '/',
        }))
    })

    it('should allow access to route:method when all routes denied and route:method allowed', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'route:0'])
        accessControl.setRule(['all', 'route:/:get:1'])
        // check access
        assert.isTrue(accessControl.allowRoute({
            method: 'get',
            path: '/',
        }))
    })

    it('should override general rules with method specific rules', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'route:/foo/bar:0'])
        accessControl.setRule(['all', 'route:/foo/bar:get:1'])
        // check access
        assert.isTrue(accessControl.allowRoute({
            method: 'get',
            path: '/foo/bar',
        }))
    })

    it('should apply rules to child paths', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'route:0'])
        accessControl.setRule(['all', 'route:/foo:get:1'])
        // check access
        assert.isTrue(accessControl.allowRoute({
            method: 'get',
            path: '/foo/bar',
        }))
    })

    it('should deny child path when parent allowed', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'route:0'])
        accessControl.setRule(['all', 'route:/foo:1'])
        accessControl.setRule(['all', 'route:/foo/bar:0'])
        // check access
        assert.isFalse(accessControl.allowRoute({
            method: 'get',
            path: '/foo/bar',
        }))
    })

    it('should deny specific method when any method allowed', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // set rule
        accessControl.setRule(['all', 'route:0'])
        accessControl.setRule(['all', 'route:/foo:1'])
        accessControl.setRule(['all', 'route:/foo:post:0'])
        // check access
        assert.isTrue(accessControl.allowRoute({
            method: 'get',
            path: '/foo',
        }))
        assert.isFalse(accessControl.allowRoute({
            method: 'post',
            path: '/foo',
        }))
    })

})