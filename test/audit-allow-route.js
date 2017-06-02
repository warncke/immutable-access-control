'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - audit allow route', function () {

    var accessControl

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
        // create new instance
        accessControl = new ImmutableAccessControl({strict: false})
    })

    it('should audit allow access to route when no rules', function () {
        // check access
        assert.isTrue(accessControl.allowRoute({
            method: 'get',
            path: '/',
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'route')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [])
    })

    it('should audit deny access to route when all routes denied', function () {
        // set rule
        accessControl.setRule(['all', 'route:0'])
        // check access
        assert.isFalse(accessControl.allowRoute({
            method: 'get',
            path: '/',
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'route')
        assert.strictEqual(audit.allow, false)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {allow: false, role: 'all', ruleType: 'global', rules: {all: 0}},
        ])
    })

    it('should audit allow access to route when all routes denied and route allowed', function () {
        // set rule
        accessControl.setRule(['all', 'route:0'])
        accessControl.setRule(['all', 'route:/:1'])
        // check access
        assert.isTrue(accessControl.allowRoute({
            method: 'get',
            path: '/',
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'route')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {allow: false, role: 'all', ruleType: 'global', rules: {all: 0}},
            {allow: true, role: 'all', ruleType: 'path', rules: { all: 1 }, segment: 'index'},
        ])
    })

    it('should audit allow access to route:method when all routes denied and route:method allowed', function () {
        // set rule
        accessControl.setRule(['all', 'route:0'])
        accessControl.setRule(['all', 'route:/:get:1'])
        // check access
        assert.isTrue(accessControl.allowRoute({
            method: 'get',
            path: '/',
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'route')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {allow: false, role: 'all', ruleType: 'global', rules: {all: 0}},
            {allow: true, role: 'all', ruleType: 'method', rules: { all: 1 }, segment: 'index'},
        ])
    })

    it('should audit override general rules with method specific rules', function () {
        // set rule
        accessControl.setRule(['all', 'route:/foo/bar:0'])
        accessControl.setRule(['all', 'route:/foo/bar:get:1'])
        // check access
        assert.isTrue(accessControl.allowRoute({
            method: 'get',
            path: '/foo/bar',
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'route')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {ruleType: 'none', segment: 'foo'},
            {allow: false, role: 'all', ruleType: 'path', rules: {all: 0}, segment: 'bar'},
            {allow: true, role: 'all', ruleType: 'method', rules: { all: 1 }, segment: 'bar'},
        ])
    })

    it('should audit apply rules to child paths', function () {
        // set rule
        accessControl.setRule(['all', 'route:0'])
        accessControl.setRule(['all', 'route:/foo:get:1'])
        // check access
        assert.isTrue(accessControl.allowRoute({
            method: 'get',
            path: '/foo/bar',
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'route')
        assert.strictEqual(audit.allow, true)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {allow: false, role: 'all', ruleType: 'global', rules: {all: 0}},
            {allow: true, role: 'all', ruleType: 'method', rules: { all: 1 }, segment: 'foo'},
        ])
    })

    it('should audit deny child path when parent allowed', function () {
        // set rule
        accessControl.setRule(['all', 'route:0'])
        accessControl.setRule(['all', 'route:/foo:1'])
        accessControl.setRule(['all', 'route:/foo/bar:0'])
        // check access
        assert.isFalse(accessControl.allowRoute({
            method: 'get',
            path: '/foo/bar',
        }))
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'route')
        assert.strictEqual(audit.allow, false)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {allow: false, role: 'all', ruleType: 'global', rules: {all: 0}},
            {allow: true, role: 'all', ruleType: 'path', rules: { all: 1 }, segment: 'foo'},
            {allow: false, role: 'all', ruleType: 'path', rules: { all: 0 }, segment: 'bar'},
        ])
    })

    it('should audit deny specific method when any method allowed', function () {
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
        // get audit record
        var audit = accessControl.audit
        // validate audit record
        assert.strictEqual(audit.allowType, 'route')
        assert.strictEqual(audit.allow, false)
        assert.strictEqual(audit.complete, true)
        assert.deepEqual(audit.rules, [
            {allow: false, role: 'all', ruleType: 'global', rules: {all: 0}},
            {allow: true, role: 'all', ruleType: 'path', rules: { all: 1 }, segment: 'foo'},
            {allow: false, role: 'all', ruleType: 'method', rules: { all: 0 }, segment: 'foo'},
        ])
    })

})