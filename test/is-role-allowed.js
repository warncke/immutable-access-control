'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')
const ImmutableAccessControlNullAudit = require('../lib/immutable-access-control-null-audit')

describe('immutable-access-control - is role allowed', function () {

    var accessControl

    beforeEach(function () {
        // create new instance
        accessControl = new ImmutableAccessControl()
        // create null audit instance
        accessControl.audit = new ImmutableAccessControlNullAudit()
        // clear global singleton instance
        ImmutableAccessControl.reset()
    })

    it('should return original allowed if no applicable rules', function () {
        // get allowed with no roles or rules
        var allowed = accessControl.isRoleAllowed(true, [], {})
        // check allowed
        assert.isTrue(allowed)
    })

    it('should return false if all:0 rule set', function () {
        // get allowed with no roles or rules
        var allowed = accessControl.isRoleAllowed(true, [], {all: 0})
        // check allowed
        assert.isFalse(allowed)
    })

    it('should return true if role matches rule:1', function () {
        // get allowed with no roles or rules
        var allowed = accessControl.isRoleAllowed(false, ['foo'], {all: 0, foo: 1})
        // check allowed
        assert.isTrue(allowed)
    })

    it('should return undefined if no applicable rules and no change', function () {
        // get allowed with no roles or rules
        var allowed = accessControl.isRoleAllowed(true, [], {}, true)
        // check allowed
        assert.isUndefined(allowed)
        // get allowed with no roles or rules
        allowed = accessControl.isRoleAllowed(false, [], {}, true)
        // check allowed
        assert.isUndefined(allowed)
    })

    it('should return false if all:0 rule set and no change', function () {
        // get allowed with no roles or rules
        var allowed = accessControl.isRoleAllowed(false, [], {all: 0}, true)
        // check allowed
        assert.isFalse(allowed)
    })

    it('should return true if role matches rule:1 and no change', function () {
        // get allowed with no roles or rules
        var allowed = accessControl.isRoleAllowed(true, ['foo'], {all: 0, foo: 1}, true)
        // check allowed
        assert.isTrue(allowed)
    })

})
