'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - audit', function () {

    var accessControl

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
        // create new instance
        accessControl = new ImmutableAccessControl({strict: false})
    })

    it('should create audit record for allowModel', function () {
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'create',
            model: 'foo',
        }))
        // validate audit record
        assert.isDefined(accessControl.audit)
        assert.isDefined(accessControl.audit.accessControlId)
        assert.strictEqual(accessControl.audit.allowType, 'model')
    })

    it('should create audit record for allowModule', function () {
        // check access
        assert.isTrue(accessControl.allowModule({
            method: 'bar',
            module: 'foo',
        }))
        // validate audit record
        assert.isDefined(accessControl.audit)
        assert.isDefined(accessControl.audit.accessControlId)
        assert.strictEqual(accessControl.audit.allowType, 'module')
    })

    it('should create audit record for allowRoute', function () {
        // check access
        assert.isTrue(accessControl.allowRoute({
            method: 'get',
            path: '/',
        }))
        // validate audit record
        assert.isDefined(accessControl.audit)
        assert.isDefined(accessControl.audit.accessControlId)
        assert.strictEqual(accessControl.audit.allowType, 'route')
    })

    it('should create audit record for allowModelScope', function () {
        // get scope
        var scope = accessControl.allowModelScope({
            action: 'list',
            model: 'foo',
        })
        // validate audit record
        assert.isDefined(accessControl.audit)
        assert.isDefined(accessControl.audit.accessControlId)
        assert.strictEqual(accessControl.audit.allowType, 'modelScope')
    })

})