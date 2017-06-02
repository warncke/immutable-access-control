'use strict'

const chai = require('chai')
const assert = chai.assert

const ImmutableAccessControl = require('../lib/immutable-access-control')

describe('immutable-access-control - replace rules', function () {

    var accessControl

    beforeEach(function () {
        // clear global singleton instance
        ImmutableAccessControl.reset()
        // create new instance
        accessControl = new ImmutableAccessControl()
    })

    it('should replace existing dynamic rules', function () {
        // set rule
        accessControl.setRule(['all', 'model:bar:0'])
        // replace rules
        accessControl.replaceRules([
            ['all', 'model:foo:0']
        ])
        // check rules
        assert.deepEqual(accessControl.rules.model.model, { foo: { allow: { all: 0 } } })
    })

    it('should not replace default rules', function () {
        // set rule
        accessControl.setRule(['all', 'model:bar:0'], true)
        // replace rules
        accessControl.replaceRules([
            ['all', 'model:foo:0']
        ])
        // check rules
        assert.deepEqual(accessControl.rules.model.model, {
            bar: { allow: { all: 0 } },
            foo: { allow: { all: 0 } },
        })
    })

    it('should keep access id names', function () {
        // set access id name
        accessControl.setAccessIdName('foo', 'bar')
        // set rule
        accessControl.setRule(['all', 'model:bar:0'], true)
        // replace rules
        accessControl.replaceRules([
            ['all', 'model:foo:0']
        ])
        // check access id name
        assert.deepEqual(accessControl.accessIdNames, {foo: 'bar'})
    })

    it('should clear id when replacing rules', function () {
        // set rule
        accessControl.setRule(['all', 'model:bar:0'], true)
        // replace rules
        accessControl.replaceRules([
            ['all', 'model:foo:0']
        ])
        // check id
        assert.isUndefined(accessControl.id)
    })

    it('should not replace rules if exception thrown', function () {
        // set rule
        accessControl.setRule(['all', 'model:bar:0'], true)
        // catch error
        var error
        try {
            // replace rules - should throw
            accessControl.replaceRules([
                ['foo', 'model:foo:0']
            ])
        }
        catch (err) {
            error = err
        }
        // check that error thrown
        assert.isDefined(error)
        // original rules should still be set
        assert.deepEqual(accessControl.rules.model.model, {
            bar: { allow: { all: 0 } },
        })
    })

})