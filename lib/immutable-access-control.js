'use strict'

/* native modules */
const assert = require('assert')

/* npm modules */
const _ = require('lodash')

/* exports */
module.exports = ImmutableAccessControl

/* constants */

// valid resource types for access control rules - map of name used in rule
// to function for setting rule
const resourceTypes = {
    '*': setRuleAny,
    model: setRuleModel,
    module: setRuleModule,
    route: setRuleRoute,
}

/**
 * @function ImmutableAccessControl
 *
 * instantiate or return global singleton access control instance. optionally
 * set access control rules.
 *
 * @param {array} rules
 *
 * @returns {ImmutableAccessControl}
 *
 * @throws {Error}
 */
function ImmutableAccessControl (rules) {
    // return global singleton if it exists
    if (global.__immutable_access_control__) {
        return global.__immutable_access_control__
    }
    // initialize new instance
    else {
        // store new instance as global singleton
        global.__immutable_access_control__ = this
        // id will be calculated from rules after they are set
        this.id = undefined
        // rules object is a map of resources and roles 
        this.rules = {}
    }
}

/* public methods */
ImmutableAccessControl.prototype = {
    setRule: setRule,
    setRules: setRules,
}

// clear global singleton data
ImmutableAccessControl.reset = function () {
    global.__immutable_access_control__ = undefined
}

/**
 * @function setRule
 *
 * set an access control rule. rule must be array with one or more role names
 * followed by a single access control rule string.
 *
 * @param {array} rule
 *
 * @throws {Error}
 */
function setRule (rule) {
    // capture original rule as string for error logging
    var origRule = rule.join(',')
    // require array
    assert.ok(Array.isArray(rule), 'rule array required')
    // get roles array
    var roles = rule
    // get rule string from last element in array
    rule = roles.pop()
    // require rule to be a string
    assert.ok(typeof rule === 'string', 'invalid rule '+origRule)
    // require at least one role
    assert.ok(roles.length, 'one or more roles required '+origRule)
    // split rule on colon to separate into clauses
    var ruleClauses = rule.split(':')
    // first clause must identify type of resource
    var resourceType = ruleClauses.shift()
    // get index of last element in rule
    var lastIdx = ruleClauses.length - 1
    // final element in rule must be 1 or 0 to indicate allow or deny
    var allow = parseInt(ruleClauses[lastIdx])
    // validate
    assert.ok(allow === 0 || allow === 1, 'allow must be 0 or 1 '+origRule)
    // set value to boolean
    ruleClauses[lastIdx] = allow
    // deny rule only allowed on all role
    if (allow === 0) {
        assert.ok(roles.length === 1 && roles[0] === 'all', 'deny can only be set for all role '+origRule)
    }
    // require valid resource type
    assert.ok(resourceTypes[resourceType], 'invalid resource type '+origRule)
    // create entry from resource type if it does not exist
    if (!this.rules[resourceType]) {
        this.rules[resourceType] = {}
    }
    // call type specific method to set rule
    resourceTypes[resourceType](roles, ruleClauses, this.rules[resourceType], origRule)
}

/**
 * @function setRules
 *
 * set access control rules. rules must be array of strings. error will be
 * thrown on invalid rule.
 * 
 * @param {array} rules
 *
 * @throws {Error}
 */
function setRules (rules) {
    // clear id for existing rules - will be recalculated after rules are set
    this.id = undefined
    // require array
    assert.ok(Array.isArray(rules), 'rules array required')
    // add each rule
    _.each(rules, rule => this.setRule(rule))
}

/* private functions */

/**
 * @function setRuleAny
 *
 * set rule that applies to all resource types
 *
 * @param {array} roles
 * @param {array} rule
 * @param {object} rules
 * @param {string} origRule
 *
 * @throws {Error}
 */
function setRuleAny (roles, rule, rules, origRule) {
    // any rule cannot have any additional clauses
    assert.ok(rule.length === 1, '* rule must have single clause '+rule.join(':'))
    // create role access rule map
    if (!rules.allow) {
        rules.allow = {}
    }
    // set rule
    _.each(roles, role => {
        rules.allow[role] = rule[0]
    })
}

/**
 * @function setRuleModel
 *
 * set model rule
 *
 * @param {array} roles
 * @param {array} rule
 * @param {object} rules
 * @param {string} origRule
 *
 * @throws {Error}
 */
function setRuleModel (roles, rule, rules, origRule) {
    // allow/deny is last element of rule
    var allow = rule.pop()
    // blanket rule for all models
    if (rule.length === 0) {
        // create role access rule map
        if (!rules.allow) {
            rules.allow = {}
        }
        // set rule for each role
        _.each(roles, role => {
            rules.allow[role] = allow
        })
        // break
        return
    }

    // model name is first clause of rule
    var model = rule.shift()
    // create map of models
    if (!rules.model) {
        rules.model = {}
    }
    // create entry for model
    if (!rules.model[model]) {
        rules.model[model] = {}
    }

    // blanket rule for single model
    if (rule.length === 0) {
        // create role access rule map
        if (!rules.model[model].allow) {
            rules.model[model].allow = {}
        }
        // set rule for each role
        _.each(roles, role => {
            rules.model[model].allow[role] = allow
        })
        // break
        return
    }

    // action follows model name
    var action = rule.shift()
    // create map of actions
    if (!rules.model[model].action) {
        rules.model[model].action = {}
    }
    // create entry for action
    if (!rules.model[model].action[action]) {
        rules.model[model].action[action] = {}
    }

    // create action does not have any options
    if (action === 'create') {
        // there should be no more rule clauses
        if (rule.length === 0) {
            // create role access rule map
            if (!rules.model[model].action[action].allow) {
                rules.model[model].action[action].allow = {}
            }
            // set rule for each role
            _.each(roles, role => {
                rules.model[model].action[action].allow[role] = allow
            })
            // break
            return
        }
        else {
            throw new Error('invalid rule '+origRule)
        }
    }
    // all other actions apply to existing model instances and can
    // apply either to any instance or to instances owned by session
    else {
        // there must be one additional rule clause
        if (rule.length === 1) {
            var scope = rule.shift()
            // scope must be own or any
            assert.ok(scope === 'own' || scope === 'any', 'invalid rule '+origRule)
            // create map for scope
            if (!rules.model[model].action[action][scope]) {
                rules.model[model].action[action][scope] = {}
            }
            // create role access rule map
            if (!rules.model[model].action[action][scope].allow) {
                rules.model[model].action[action][scope].allow = {}
            }
            // set rule for each role
            _.each(roles, role => {
                rules.model[model].action[action][scope].allow[role] = allow
            })
        }
        else {
            throw new Error('invalid rule '+origRule)
        }
    }
}

/**
 * @function setRuleModule
 *
 * set module rule
 *
 * @param {array} roles
 * @param {array} rule
 * @param {object} rules
 * @param {string} origRule
 *
 * @throws {Error}
 */
function setRuleModule (roles, rule, rules, origRule) {
    // allow/deny is last element of rule
    var allow = rule.pop()
    // blanket rule for all modules
    if (rule.length === 0) {
        // create role access rule map
        if (!rules.allow) {
            rules.allow = {}
        }
        // set rule for each role
        _.each(roles, role => {
            rules.allow[role] = allow
        })
        // break
        return
    }

    // module name is first clause of rule
    var module = rule.shift()
    // create map of models
    if (!rules.module) {
        rules.module = {}
    }
    // create entry for module
    if (!rules.module[module]) {
        rules.module[module] = {}
    }

    // blanket rule for single module
    if (rule.length === 0) {
        // create role access rule map
        if (!rules.module[module].allow) {
            rules.module[module].allow = {}
        }
        // set rule for each role
        _.each(roles, role => {
            rules.module[module].allow[role] = allow
        })
    }
    // rule for method
    else if (rule.length === 1) {
        var method = rule.shift()
        // create map of methods
        if (!rules.module[module].method) {
            rules.module[module].method = {}
        }
        // create method entry
        if (!rules.module[module].method[method]) {
            rules.module[module].method[method] = {}
        }
        // create role access rule map
        if (!rules.module[module].method[method].allow) {
            rules.module[module].method[method].allow = {}
        }
        // set rule for each role
        _.each(roles, role => {
            rules.module[module].method[method].allow[role] = allow
        })
    }
    // invalid rule
    else {
        throw new Error('invalid rule '+origRule)
    }
}

/**
 * @function setRuleRoute
 *
 * set route rule
 *
 * @param {array} roles
 * @param {array} rule
 * @param {object} rules
 * @param {string} origRule
 *
 * @throws {Error}
 */
function setRuleRoute (roles, rule, rules, origRule) {
    // allow/deny is last element of rule
    var allow = rule.pop()
    // blanket rule for all models
    if (rule.length === 0) {
        // create role access rule map
        if (!rules.allow) {
            rules.allow = {}
        }
        // set rule for each role
        _.each(roles, role => {
            rules.allow[role] = allow
        })
        // break
        return
    }

    // path name is first clause of rule
    var path = rule.shift()
    // path must start with /
    assert.ok(path.charAt(0) === '/', 'path must start with slash '+origRule)
    // split path into segments
    var segments = path.split('/')
    // discard first empty segment of path
    segments.shift()
    // require atleast one path segment
    assert.ok(segments[0].length, 'invalid path '+origRule)
    // path rule starts from root of rools structure and will be nested
    // as many layers deep as there are segments
    var pathRule = rules
    // iterate over each path segment creating nested rule
    _.each(segments, segment => {
        // create map of paths
        if (!pathRule.path) {
            pathRule.path = {}
        }
        // create entry for path
        if (!pathRule.path[segment]) {
            pathRule.path[segment] = {}
        }
        // move pathRule cursor to nested structure
        pathRule = pathRule.path[segment]
    })
    // blanket rule for single path
    if (rule.length === 0) {
        // create role access rule map
        if (!pathRule.allow) {
            pathRule.allow = {}
        }
        // set rule for each role
        _.each(roles, role => {
            pathRule.allow[role] = allow
        })
    }
    // rule for method
    else if (rule.length === 1) {
        var method = rule.shift()
        // create map of methods
        if (!pathRule.method) {
            pathRule.method = {}
        }
        // create method entry
        if (!pathRule.method[method]) {
            pathRule.method[method] = {}
        }
        // create role access rule map
        if (!pathRule.method[method].allow) {
            pathRule.method[method].allow = {}
        }
        // set rule for each role
        _.each(roles, role => {
            pathRule.method[method].allow[role] = allow
        })
    }
    // invalid rule
    else {
        throw new Error('invalid rule '+origRule)
    }
}