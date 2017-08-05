'use strict'

/* native modules */
const assert = require('assert')

/* npm modules */
const _ = require('lodash')
const debug = require('debug')('immutable-access-control')
const defined = require('if-defined')
const requireValidOptionalObject = require('immutable-require-valid-optional-object')
const stableId = require('stable-id')

/* application modules */
const ImmutableAccessControlAudit = require('./immutable-access-control-audit')
const ImmutableAccessControlNullAudit = require('./immutable-access-control-null-audit')

/* exports */
module.exports = ImmutableAccessControl

/* constants */

// valid resource types for access control rules - map of name used in rule
// to function for setting rule
const resourceTypes = {
    model: setRuleModel,
    module: setRuleModule,
    route: setRuleRoute,
}

/**
 * @function ImmutableAccessControl
 *
 * instantiate or return global singleton access control instance.
 *
 * @param {object} args
 *
 * @returns {ImmutableAccessControl}
 *
 * @throws {Error}
 */
function ImmutableAccessControl (args) {
    // make sure args are object
    args = requireValidOptionalObject(args)
    // return global singleton if it exists
    if (args.global !== false && global.__immutable_access_control__) {
        return global.__immutable_access_control__
    }
    // initialize new instance
    else {
        // store new instance as global singleton
        if (args.global !== false) {
            global.__immutable_access_control__ = this
        }
        // id will be calculated from rules after they are set
        this.id = undefined
        // names of properties use for determining ownership of model records
        // map of model name -> property name - default is accountId
        this.accessIdNames = {}
        // list of rules set with default flag
        this.defaultRules = []
        // rules object is a map of resources and roles 
        this.rules = {}
        // use strict mode by default which will throw error if requesting
        // access without a valid session
        this.strict = args.strict === undefined ? true : !!args.strict
        // audit will be create for each allow request
        this.audit = undefined
        // audit enabled by default
        this.auditEnabled = args.audit === false ? false : true
    }
}

/* public methods */
ImmutableAccessControl.prototype = {
    allowModel: allowModel,
    allowModelScope: allowModelScope,
    allowModule: allowModule,
    allowRoute: allowRoute,
    getAccessIdName: getAccessIdName,
    getId: getId,
    getRoles: getRoles,
    getRules: getRules,
    isRoleAllowed: isRoleAllowed,
    newAudit: newAudit,
    replaceRules: replaceRules,
    requireValidArgsModel: requireValidArgsModel,
    requireValidArgsModule: requireValidArgsModule,
    requireValidArgsRoute: requireValidArgsRoute,
    requireValidSession: requireValidSession,
    setAccessIdName: setAccessIdName,
    setRule: setRule,
    setRules: setRules,
    // class properties
    class: 'ImmutableAccessControl',
    ImmutableAccessControl: true,
}

// clear global singleton data
ImmutableAccessControl.reset = function () {
    global.__immutable_access_control__ = undefined
}

/**
 * @function allowModel
 *
 * check whether or not session is allowed access to model
 *
 * @param {object} args
 * @param {string} args.accessId
 * @param {string} args.action
 * @param {string} args.model
 * @param {string} args.scope
 * @param {object} args.session
 * @param {array} args.states
 *
 * @returns {boolean}
 *
 * @throws {Error}
 */
function allowModel (args) {
    // validate args
    this.requireValidArgsModel(args)
    // start new audit
    this.newAudit(args, 'model')
    // get states array from args if any
    var states = args.states
    // set deleted flag if request is for deleted state
    var deleted = states && states.includes('deleted') ? true : false
    // audit deleted state
    this.audit.setRule({
        deleted: deleted,
        allow: !deleted,
    })
    // get access rules
    var rules = this.getRules('model')
    // if no rules exist for model then default to allow
    if (!rules) {
        // default to allow accept for deleted state
        return this.audit.setAllow(deleted ? false : true)
    }
    // get roles from session or use defaults
    var roles = this.getRoles(args.session)
    // default to allow
    var allow = true
    // check global rules
    if (rules.allow) {
        allow = this.isRoleAllowed(allow, roles, rules.allow, false, 'global')
    }
    // get model specific rules
    rules = rules.model && rules.model[args.model]
    // if there are no model specific rules then return current allow
    if (!rules) {
        // return current allow state or false if deleted
        return this.audit.setAllow(deleted ? false : allow)
    }
    // check model specific rule
    if (rules.allow) {
        allow = this.isRoleAllowed(allow, roles, rules.allow, false, 'model')
    }
    // get action specific rules
    rules = rules.action && rules.action[args.action]
    // if there are no action specific rules then return current allow
    if (!rules) {
        // return current allow state or false if deleted
        return this.audit.setAllow(deleted ? false : allow)
    }
    // check action specific rule
    if (rules.allow) {
        allow = this.isRoleAllowed(allow, roles, rules.allow, false, 'action')
    }
    // create action has no ownership scope so return current allow value
    if (args.action === 'create') {
        // return current allow state - there can be no deleted state for
        // create so ignore deleted
        return this.audit.setAllow(allow)
    }
    // the request scope is based on either a specific record instance and
    // whether or not the requesting session owns that instance or on an
    // abstract request for whether or not the session would be allowed to
    // access the given scope
    var scope
    // access is being requested to a specific record
    if (args.accessId) {
        // get access id from session
        var sessionAccessId = args.session
            && args.session[this.getAccessIdName(args.model)]
        // if session owns record then scope is own
        scope = args.accessId === sessionAccessId ? 'own' : 'any'
    }
    // scope access is being requested in the abstract as opposed to for a
    // specific record
    else if (args.scope) {
        scope = args.scope
    }
    // in strict mode an error would be throw if neither scope or accessId
    // provided for non-create action - in non-strict mode default to any
    else {
        scope = 'any'
    }
    // if access request is for a specific instance with one or more states
    // then current session must be allowed access for ALL of those states
    if (states) {
        // get number of states
        var statesLen  = states.length
        // check acess for each state
        for (var i=0; i < statesLen; i++) {
            var state = states[i]
            // set flag to indicate if the state is deleted
            var deleted = state === 'deleted'
            // deleted is special system state that defaults to deny
            if (deleted) {
                allow = false
            }
            // get state rules
            var stateRules = rules.state && rules.state[state]
            // there are no rules for this state
            if (!stateRules) {
                // if there are no rules to override default deny on deleted
                // then return deny
                if (deleted) {
                    return this.audit.setAllow(false)
                }
                // evaluate next state if any
                else {
                    continue
                }
            }
            // get any rules
            var anyRules = stateRules.any && stateRules.any.allow
            // any scope includes own scope so test first
            if (anyRules) {
                // pass changed flag so that undefined will be returned unless
                // allow state was changed by matching rule
                var allowAny = this.isRoleAllowed(allow, roles, anyRules, true, 'state', {
                    allowScope: scope,
                    ruleScope: 'any',
                    state: state,
                })
                // rule specifically allows access
                if (allowAny === true) {
                    // allow on any applies to both any and own no matter what
                    // scope was requested
                    allow = true
                    // evaluate next state if any
                    continue
                }
                // rule specifically denies access 
                else if (allowAny === false) {
                    // if any scope was requested then access is denied
                    if (scope === 'any') {
                        return this.audit.setAllow(false)
                    }
                }
            }
            // get own rules
            var ownRules = stateRules.own && stateRules.own.allow
            // if access not allowed by any scope then evaluate own scope
            if (ownRules) {
                // pass changed flag so that undefined will be returned unless
                // allow state was changed by matching rule
                var allowOwn = this.isRoleAllowed(allow, roles, ownRules, true, 'state', {
                    allowScope: scope,
                    ruleScope: 'own',
                    state: state,
                })
                // rule specifically allows access
                if (allowOwn === true) {
                    // if the request scope is own then allow
                    if (scope === 'own') {
                        allow = true
                        // evaluate next state
                        continue
                    }
                }
                // rule specifically denies access
                else if (allowOwn === false) {
                    // a deny on own also applies to any
                    return this.audit.setAllow(false)
                }
            }
            // if any is denied and own not allowed then deny
            if (allowAny === false) {
                return this.audit.setAllow(false)
            }
            // if state is deleted and no rule specifically allowed then deny
            if (deleted) {
                return this.audit.setAllow(false)
            }
        }
    }
    // if access determination is not made based on state then evaluate general
    // rules that apply to all states
    var anyRules = rules.any && rules.any.allow
    // evaluate any rules
    if (anyRules) {
        // check access for any role
        var allowAny = this.isRoleAllowed(allow, roles, anyRules, true, 'action', {
            allowScope: scope,
            ruleScope: 'any',
        })
        // if any allowed then access is allowed for both any and own
        if (allowAny === true) {
            return this.audit.setAllow(true)
        }
        else if (allowAny === false) {
            // if any not allowed and any was requested then deny
            if (scope === 'any') {
                return this.audit.setAllow(false)
            }
            // if own scope requested and any denied then will be denied
            // for own unless specifically allowed
            else {
                allow = allowAny
            }
        }
    }
    // get own rules
    var ownRules = rules.own && rules.own.allow
    // if there are own rules and scope is own then apply them
    if (ownRules && scope === 'own') {
        allow = this.isRoleAllowed(allow, roles, ownRules, false, 'action', {
            allowScope: scope,
            ruleScope: 'own',
        })
    }
    // return final decision
    return this.audit.setAllow(allow)
}

/**
 * @function allowModelScope
 *
 * get the scope allowed for a model action. this will be either any, own,
 * or undefined if no scope is allowed.
 *
 * scope is determined by calling allowModel first with a scope of any and if
 * that returns false then with a scope of all.
 *
 * @param {object} args
 * @param {string} args.accessId
 * @param {string} args.action
 * @param {string} args.model
 * @param {string} args.scope
 * @param {object} args.session
 * @param {array} args.states
 *
 * @returns {string|undefined}
 */
function allowModelScope (args) {
    // start new audit
    this.newAudit(args, 'modelScope')
    // check any scope
    args.scope = 'any'
    // check access
    var allow = this.allowModel(args)
    // access to any is allowed
    if (allow) {
        return this.audit.setScope('any')
    }
    // check own scope
    args.scope = 'own'
    // check access
    var allow = this.allowModel(args)
    // return own if allowed or undefined if denied
    return this.audit.setScope(allow ? 'own' : undefined)
}

/**
 * @function allowModule
 *
 * check whether or not session is allowed access to module
 *
 * @param {object} args
 *
 * @returns {boolean|string}
 *
 * @throws {Error}
 */
function allowModule (args) {
    // validate args
    this.requireValidArgsModule(args)
    // start new audit
    this.newAudit(args, 'module')
    // get access rules
    var rules = this.getRules('module')
    // if no rules exist for modules then default to allow
    if (!rules) {
        return this.audit.setAllow(true)
    }
    // get roles from session or use defaults
    var roles = this.getRoles(args.session)
    // default to allow
    var allow = true
    // check global rules
    if (rules.allow) {
        allow = this.isRoleAllowed(allow, roles, rules.allow, false, 'global')
    }
    // get module specific rules
    rules = rules.module && rules.module[args.module]
    // if there are no module specific rules then return current allow
    if (!rules) {
        return this.audit.setAllow(allow)
    }
    // check module specific rule
    if (rules.allow) {
        allow = this.isRoleAllowed(allow, roles, rules.allow, false, 'module')
    }
    // get method specific rules
    rules = rules.method && rules.method[args.method]
    // if there are no method specific rules then return current allow
    if (!rules) {
        return this.audit.setAllow(allow)
    }
    // check method specific rule
    if (rules.allow) {
        allow = this.isRoleAllowed(allow, roles, rules.allow, false, 'method')
    }

    return this.audit.setAllow(allow)
}

/**
 * @function allowRoute
 *
 * check whether or not session has access to route
 *
 * @function {object} args
 *
 * @returns {boolean}
 *
 * @throws {Error}
 */
function allowRoute (args) {
    // validate args
    this.requireValidArgsRoute(args)
    // start new audit
    this.newAudit(args, 'route')
    // get access rules
    var rules = this.getRules('route')
    // if no rules exist for model then default to allow
    if (!rules) {
        return this.audit.setAllow(true)
    }
    // get path
    var path = args.path
    // if path ends in / append index
    if (path.charAt(path.length - 1) === '/') {
        path = path + 'index';
    }
    // split path into segments
    var segments = path.split('/')
    // discard first empty segment of path
    segments.shift()
    // get roles from session or use defaults
    var roles = this.getRoles(args.session)
    // default to allow
    var allow = true
    // check global rules
    if (rules.allow) {
        allow = this.isRoleAllowed(allow, roles, rules.allow, false, 'global')
    }
    // get number of segments
    var segmentsLen = segments.length
    // check each path segment to see if it has any rules
    for (var i=0; i<segmentsLen; i++) {
        // get next segment
        var segment = segments[i]
        // get rules for path segment if any
        rules = rules.path && rules.path[segment]
        // if there are rules check them
        if (rules) {
            // set to true if segment has any rules
            var hasRules = false
            // if there are rules that apply to all methods check them
            if (rules.allow) {
                allow = this.isRoleAllowed(allow, roles, rules.allow, false, 'path', {
                    segment: segment,
                })
                hasRules = true
            }
            // if there is a method specific rule for route that matches
            // the method being requested then check it - this overrides
            // any non method specific rule
            if (rules.method && rules.method[args.method]) {
                allow = this.isRoleAllowed(allow, roles, rules.method[args.method].allow, false, 'method', {
                    segment: segment,
                })
                hasRules = true
            }
            // if segment has no rules then add audit record to indicate this
            if (!hasRules) {
                this.audit.setRule({
                    ruleType: 'none',
                    segment: segment,
                })
            }
        }
        // if there are no rules for this segment then there can be not rules
        // for any child segment so return current allow status
        else {
            return this.audit.setAllow(allow)
        }
    }

    return this.audit.setAllow(allow)
}

/**
 * @function getAccessIdName
 *
 * get name of property used for accessId. default accountId.
 *
 * @param {string} model
 *
 * @returns {string}
 */
function getAccessIdName (model) {
    return this.accessIdNames[model] ? this.accessIdNames[model] : 'accountId'
}

/**
 * @function getId
 *
 * return id creating if needed.
 *
 * @returns {string}
 */
function getId () {
    // calculate id if not set
    if (!this.id) {
        // get unique id for all data that determines access control
        this.id = stableId(_.pick(this, ['accessIdNames', 'rules']))
    }
    // return id
    return this.id
}

/**
 * @function getRoles
 *
 * get roles from session or use defaults. default roles are all and either
 * authenticated or anonymous based on whether or not session has accountId.
 *
 * @param {object} session
 *
 * @returns {array}
 */
function getRoles (session) {
    // return roles from session or default
    return session && Array.isArray(session.roles)
        ? session.roles
        // default roles
        : ['all', (session && session.accountId ? 'authenticated' : 'anonymous')]
}

/**
 * @function getRules
 *
 * returns current access control rules. if id is not set it is calculated.
 * if resourceType is passed will return only rules for that resourceType.
 * if no rules exist for resourceType then undefined will be returned.
 *
 * @param {string} resourceType
 *
 * @returns {object|undefined}
 */
function getRules (resourceType) {
    // make sure id is generated
    this.getId()
    // return rules for resource type if set or all rules
    return resourceType ? this.rules[resourceType] : this.rules
}

/**
 * @function isRoleAllowed
 *
 * takes current allow status, session roles, and set of access control rules
 * and determines whether or not session is allowed based on these inputs.
 *
 * the previous value of allow will be returned unless there is a specific rule
 * that causes it to be changed.
 *
 * allow can only be changed to false by a rule on the all role.
 *
 * allow can only be changed to true if there is a rule for a role the session
 * has that allows access.
 *
 * if the optional matched flag is set then allow/deny will only be returned if
 * a rule was matched and undefined will be returned if no matching rules.
 *
 * @param {boolean} allow
 * @param {array} roles
 * @param {object} rules
 * @param {boolean} matched
 * @param {string} ruleType
 * @param {object|undefined} auditData
 *
 * @returns {boolean|undefined}
 */
function isRoleAllowed (allow, roles, rules, matched, ruleType, auditData) {
    // get length of roles for iteration
    var rolesLen = roles.length
    // check if user has any role that allows access
    for (var i=0; i < rolesLen; i++) {
        // if session has role that allows access then this overrides whatever
        // the previous value of allow was and any deny rule on all
        if (rules[roles[i]] === 1) {
            // build audit record
            var auditRule = {
                allow: true,
                role: roles[i],
                ruleType: ruleType,
                rules: rules,
            }
            // add additional audit data if any
            if (defined(auditData)) {
                _.merge(auditRule, auditData)
            }
            // store audit record
            this.audit.setRule(auditRule)
            // access is allowed
            return true
        }
    }
    // if there is a deny rule for all and there was no specific allow rule
    // then access is denied
    if (rules.all === 0) {
        // build audit record
        var auditRule = {
            allow: false,
            role: 'all',
            ruleType: ruleType,
            rules: rules,
        }
        // add additional audit data if any
        if (defined(auditData)) {
            _.merge(auditRule, auditData)
        }
        // store audit record
        this.audit.setRule(auditRule)
        // access is denied
        return false
    }
    // build audit record
    var auditRule = {
        matched: false,
        ruleType: ruleType,
        rules: rules,
    }
    // add additional audit data if any
    if (defined(auditData)) {
        _.merge(auditRule, auditData)
    }
    // store audit record
    this.audit.setRule(auditRule)
    // return previous allow value or undefined if matched flag set
    return matched ? undefined : allow
}

/**
 * @function newAudit
 *
 * create new audit record for allow request. audit is stored on global
 * object so it will be overwritten with each new allow request unless
 * saved.
 *
 * @param {object} allowArgs
 * @param {string} allowType
 */
function newAudit (allowArgs, allowType) {
    // if audit is enabled/disabled in call this overrides global setting
    if (defined(allowArgs.audit)) {
        if (allowArgs.audit === false) {
            // create null audit instance
            this.audit = new ImmutableAccessControlNullAudit()
            // abort
            return
        }
    }
    // otherwise if audit is globally disabled then create null instance
    else if (this.auditEnabled === false) {
        // create null audit instance
        this.audit = new ImmutableAccessControlNullAudit()
        // abort
        return
    }
    // if there is an existing incomplete audit of allowModelScope do
    // not start new audit for sub-call to allowModel
    if (allowType === 'model' && defined(this.audit) && this.audit.allowType === 'modelScope' && !this.audit.complete) {
        return
    }
    // create new audit record
    this.audit = new ImmutableAccessControlAudit({
        accessControlId: this.getId(),
        allowArgs: allowArgs,
        allowType: allowType,
    })
}

/**
 * @function replaceRules
 *
 * replace rules for global instance.
 *
 * @param {array} rules
 *
 * @throws {Error}
 */
function replaceRules (rules) {
    // create new non global instance
    var accessControl = new ImmutableAccessControl({global: false})
    // set default rules from current instance
    accessControl.setRules(this.defaultRules)
    // set new rules
    accessControl.setRules(rules)
    // replace local rules
    this.rules = accessControl.rules
    // clear rule id
    this.id = undefined
}

/**
 * @function requireValidArgsModel
 *
 * throw error if args are not valid for allowModel
 *
 * @param {object} args
 *
 * @throws {Error}
 */
function requireValidArgsModel (args) {
    // do not check if strict mode not set
    if (!this.strict) {
        return
    }
    // require valid session
    this.requireValidSession(args.session)
    // require specific model and action to be defined for request
    assert.ok(typeof args.model === 'string' && typeof args.action === 'string', 'model and action required to request access for model')
    // require valid scope on actions other than create
    assert.ok(args.action === 'create' || args.scope === 'any' || args.scope === 'own' || args.accessId, 'scope required for actions except create to request access for model')
}

/**
 * @function requireValidArgsModule
 *
 * throw error if args are not valid for allowModel
 *
 * @param {object} args
 *
 * @throws {Error}
 */
function requireValidArgsModule (args) {
    // do not check if strict mode not set
    if (!this.strict) {
        return
    }
    // require valid session
    this.requireValidSession(args.session)
    // require module and method
    assert.ok(typeof args.module === 'string' && typeof args.method === 'string', 'module and method required to request access for module')
}

/**
 * @function requireValidArgsRoute
 *
 * throw error if args not valid for allowRoute
 *
 * @param {object} args
 *
 * @throws {Error}
 */
function requireValidArgsRoute (args) {
    // do not check if strict mode not set
    if (!this.strict) {
        return
    }
    // require valid session
    this.requireValidSession(args.session)
    // require route and method
    assert.ok(typeof args.path === 'string' && typeof args.method === 'string', 'route and method required to request access for route')
    // path must start with /
    assert.ok(args.path.charAt(0) === '/', 'path must start with slash')
}

/**
 * @function requireValidSession
 *
 * throw error if not session with id and roles
 *
 * @param {object} session
 *
 * @throws {Error}
 */
function requireValidSession (session) {
    assert.ok(session && typeof session === 'object' && typeof session.sessionId === 'string' && Array.isArray(session.roles), 'session with sessionId and roles required to request access')
}

/**
 * setAccessIdName
 *
 * set the column/property name used for determining ownership for model
 *
 * @param {string} model
 * @param {string} accessIdName
 *
 * @throws {Error}
 */
function setAccessIdName (model, accessIdName) {
    // validate args
    assert.ok(typeof model === 'string', 'model name required')
    assert.ok(typeof accessIdName === 'string', 'access id property name required')
    // set property name
    this.accessIdNames[model] = accessIdName
}

/**
 * @function setRule
 *
 * set an access control rule. rule must be array with one or more role names
 * followed by a single access control rule string.
 *
 * @param {array} rule
 * @param {boolean} isDefault
 *
 * @throws {Error}
 */
function setRule (rule, isDefault) {
    // clear id for existing rules
    this.id = undefined
    // if this is default rule then add to list
    if (isDefault) {
        this.defaultRules.push(_.cloneDeep(rule))
    }
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
    debug('set rules', rules)
    // require array
    assert.ok(Array.isArray(rules), 'rules array required')
    // add each rule
    _.each(rules, rule => this.setRule(rule))
}

/* private functions */

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
        // if there are two rule clauses then next is a state
        if (rule.length === 2) {
            var state = rule.shift()
            // create map of states
            if (!rules.model[model].action[action].state) {
                rules.model[model].action[action].state = {}
            }
            // create entry for state
            if (!rules.model[model].action[action].state[state]) {
                rules.model[model].action[action].state[state] = {}
            }
            // own/any clause follows state
            rules = rules.model[model].action[action].state[state]
        }
        // otherwise own/any clause follows action
        else {
            rules = rules.model[model].action[action]
        }
        // there must be one additional rule clause
        if (rule.length === 1) {
            var scope = rule.shift()
            // scope must be own or any
            assert.ok(scope === 'own' || scope === 'any', 'invalid rule '+origRule)
            // create map for scope
            if (!rules[scope]) {
                rules[scope] = {}
            }
            // create role access rule map
            if (!rules[scope].allow) {
                rules[scope].allow = {}
            }
            // set rule for each role
            _.each(roles, role => {
                rules[scope].allow[role] = allow
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
    // if path ends in / append index
    if (path.charAt(path.length - 1) === '/') {
        path = path + 'index';
    }
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