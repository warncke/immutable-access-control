'use strict'

/* native modules */
const assert = require('assert')

/* npm modules */
const _ = require('lodash')
const debug = require('debug')('immutable-access-control')
const defined = require('if-defined')

/* exports */
module.exports = ImmutableAccessControlAudit

/* constants */
const validAllowTypes = {
    model: true,
    modelScope: true,
    module: true,
    route: true,
}

/**
 * @function ImmutableAccessControlAudit
 *
 * create new audit instance
 *
 * @param {object} args
 *
 * @returns {ImmutableAccessControlAudit}
 *
 * @throws {Error}
 */
function ImmutableAccessControlAudit (args) {
    // require access control id
    assert.ok(defined(args.accessControlId), 'accessControlId required')
    // require valid allow type
    assert.ok(defined(validAllowTypes[args.allowType]), `invalid allowType ${args.allowType}`)
    // initialize aduit record
    this.accessControlId = args.accessControlId
    this.allowArgs = args.allowArgs
    this.allowType = args.allowType
    // list of evaluated rules
    this.rules = []
    // optional boolean for whether or not access allowed
    this.allow = undefined
    // optional scope that access allowed for
    this.scope = undefined
    // set to true when allow request resolved
    this.complete = false
}

/* public methods */
ImmutableAccessControlAudit.prototype = {
    setAllow: setAllow,
    setRule: setRule,
    setScope: setScope,
}

/**
 * @function setAllow
 *
 * set whether or not access allowed. returns value set.
 *
 * @param {boolean} allow
 *
 * @returns {boolean}
 *
 * @throws {Error}
 */
function setAllow (allow) {
    // throw error if attempting operation on complete audit record
    assert.ok(!this.complete, 'cannot setAllow on complete audit record')
    // set allow value
    this.allow = allow
    // allow request is complete - do not set for modelScope requests
    if (this.allowType !== 'modelScope') {
        this.complete = true
        // debug
        debug(this)
    }
    // return set value
    return this.allow
}

/**
 * @function setRule
 *
 * set rule that was evaluated.
 *
 * @param {object} rule
 *
 * @throws {Error}
 */
function setRule (rule) {
    // throw error if attempting operation on complete audit record
    assert.ok(!this.complete, 'cannot setRule on complete audit record')
    // set rule
    this.rules.push(rule)
}

/**
 * @function setScope
 *
 * set scope allowed. returns value set.
 *
 * @param {boolean} allow
 *
 * @returns {boolean}
 *
 * @throws {Error}
 */
function setScope (scope) {
    // throw error if attempting operation on complete audit record
    assert.ok(!this.complete, 'cannot setScope on complete audit record')
    // set scope value
    this.scope = scope
    // allow request is complete
    this.complete = true
    // debug
    debug(this)
    // return set value
    return this.scope
}