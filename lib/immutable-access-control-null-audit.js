'use strict'

/* exports */
module.exports = ImmutableAccessControlNullAudit

/**
 * @function ImmutableAccessControlNullAudit
 *
 * create new null audit instance which has the same interface os
 * ImmutableAccessControlAudit but does nothing.
 *
 * a null audit instance can be set to disable auditing.
 *
 * @param {object} args
 *
 * @returns {ImmutableAccessControlNullAudit}
 *
 * @throws {Error}
 */
function ImmutableAccessControlNullAudit () {}

/* public methods */
ImmutableAccessControlNullAudit.prototype = {
    setAllow: setAllow,
    setRule: setRule,
    setScope: setScope,
}

function setAllow (allow) { return allow }

function setRule () {}

function setScope (scope) { return scope }