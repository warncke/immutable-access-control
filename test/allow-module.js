'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe.skip('immutable-access-control - allow module', function () {

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
    })

    it('should allow access to module when no rules', function () {
        // create new instance
        var accessControl = new ImmutableAccessControl({strict: false})
        // check access
        assert.isTrue(accessControl.allowModule({
            module: 'boo',
            method: 'bar',
        }))
    })

})