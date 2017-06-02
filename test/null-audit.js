'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')
const ImmutableAccessControlNullAudit = require('../lib/immutable-access-control-null-audit')

describe('immutable-access-control - null audit', function () {

    var accessControl

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
    })

    it('should disable audit globally', function () {
        // create new instance
        accessControl = new ImmutableAccessControl({audit: false, strict: false})
        // check access
        assert.isTrue(accessControl.allowModel({
            action: 'create',
            model: 'foo',
        }))
        // validate audit record
        assert.instanceOf(accessControl.audit, ImmutableAccessControlNullAudit)
    })

    it('should create audit record for allowModule', function () {
        // create new instance
        accessControl = new ImmutableAccessControl({strict: false})
        // check access
        assert.isTrue(accessControl.allowModule({
            audit: false,
            method: 'bar',
            module: 'foo',
        }))
        // validate audit record
        assert.instanceOf(accessControl.audit, ImmutableAccessControlNullAudit)
    })

})