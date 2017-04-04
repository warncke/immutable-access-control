# immutable-access-control

Immutable Access Control provides a role based permission system to control
access to [immutable-core](https://www.npmjs.com/package/immutable-core)
modules and methods,
[immutable-core-model](https://www.npmjs.com/package/immutable-core-model)
models and [immutable-app](https://www.npmjs.com/package/immutable-app)
routes.

Immutable Access Control is integrated with
[immutable-app-app](https://www.npmjs.com/package/immutable-app-auth)
so immutable apps that use immutable-app-auth will have Immutable Access
Control fully integrated with no additional configuration.

## Account, Auth and Session

The Immutable Access Control system is designed to integrate with the other
components of the Immutable App ecosystem and so it is easiest to understand
how Immutable Access Control works when fully integrated with those other
components.

Accounts and Sessions are fundamental to the Immutable App ecosystem.

Immutable models record the sessionId of the session that created each record
by default.

Every Immutable Core Model record should have a sessionId that identifies the
session that created the record.

By default Immutable models use the accountId to determine the ownership of a
record.

An Immutable Core Model record with an accountId is owned by that account.

The session that creates a record may have a different accountId than the
accountId that owns the record.

Having both an accountId and sessionId on a record allows for both accurate
determination of ownership and accurate tracking of who created revisions.

Sessions start out anonymous. Once a users logs in the session will be
associated with an accountId. A session can only be associated with one
accountId. If a user logs out the session they were in is ended and a new
session is created.

Account records consist only of an accountId.

In order to create an account a related Auth record must be created that
specifies the auth provider and related data that allows logging into the
account.

An account can have multiple auth records associated with it that allow logging
in from various auth providers.

Immutable App Auth supports Google, Facebook, and local password based auth
providers among others.

## Roles

All access control rules are assigned to roles. Acess control rules are never
assigned directly to accounts.

In order to give an account permission to perform an action the access rule for
that action must be assigned to a role and that role must be assigned to an
account.

### All, Anonymous and Authenticated Roles

Three system roles exist which apply to all sessions without being assigned to
an account.

The `all` role applies to all sessions and access control rules assigned to the
all role will apply to every user.

The `anonymous` role applies to all sessions that are not logged in to an
account.

The `authenticated` role applies to all sessions that are logged in to an
account.

| Session State | Default Roles         |
|---------------|-----------------------|
| Logged Out    | all, anonymous        |
| Logged In     | all, authenticated    |

In addition to the default roles that exist for all sessions once a session is
logged in then that session can have any number of additional custom roles
assigned to it.

### Permission to assign roles

Roles consist of a list of access control rules that the Role has permissions
for. The permissions that can be granted are: access, assign, and revoke.

If a role has the `access` permission only then accounts with that role will be
able to perform any of the actions defined in the access control rules
assigned to the role but they will not be able to assign or revoke those
permissions for any other account.

If a role has the `assign` permission then an account with that role will be
able to assign that role to another account or assign individual access control
rules for that role to other role if they also have role create or role update
privileges.

If a role has the `revoke` permission then an account with that role can revoke
permissions under the same conditions as they could assign them if they had
assign permissions.

Accounts can have all three role permissions (access, assign, revoke) or any
subset of those permissions.

## Applying access control rules

Immutable Access Control is permissive by default and follows a principle of
maximum permissiveness.

Actions are allowed by default and unless a specific resources is denied by
default then the roles and permissions of the accessing session will never be
evaluated.

If one of the roles associated with a session grants permission for an action
then permission will be granted.

Default deny rules must be specified either in code or under the `all` default
role.

Deny rules specified for any role other than `all` will never be evaluated and
are invalid.

## Defining access control rules

Access control rules are defined as strings that identify a resource and a
boolean value of '0' or '1' that specifies whether access is allowed or denied.

The asterix * can be used as a wildcard to match any value in an access control
rule clause.

### Granting access to everything

    *:1

This rule grants access all resources and actions. This access control rule
would typically be assigned to the super user(s) of the system.

### Access control rules for Immutable Core modules

| Rule              | Description                               |
|---------------------------------------------------------------|
| module:0          | deny access to all modules and methods    |
| module:foo:1      | allow access to all methods for foo       |
| module:bar:bam:1  | allow access to bam method for bar        |


### Access control rules for Immutable Core Models

| Rule                          | Description                                  |
|------------------------------------------------------------------------------|
| model:0                       | deny access to all models and actions        |
| model:bar:1                   | allow access to all bar actions              |
| model:bar:create:1            | allow creating new bar records               |
| model:bar:delete:own:1        | allow deleting own bar records               |
| model:bar:delete:any:1        | allow deleting any bar records               |
| model:bar:list:own:1          | allow listing own bar records                |
| model:bar:list:any:1          | allow listing any bar records                |
| model:bar:list:deleted:own:1  | allow listing own deleted bar records        |
| model:bar:list:deleted:any:1  | allow listing any deleted bar records        |
| model:bar:read:own:1          | allow viewing own bar records                |
| model:bar:read:any:1          | allow viewing any bar records                |
| model:bar:read:deleted:own:1  | allow viewing own deleted bar records        |
| model:bar:read:deleted:any:1  | allow viewing any deleted bar records        |
| model:bar:update:own:1        | allow updating own bar records               |
| model:bar:update:any:1        | allow updating any bar records               |
| model:bar:chown:own:1         | allow changing ownership of own bar records  |
| model:bar:chown:any:1         | allow changing ownership of any bar records  |
| model:bar:<action>:own:1      | allow performing action for own bar records  |
| model:bar:<action>:any:1      | allow performing action for any bar records  |

Immutable Core Models use Immutable Core modules to perform their low level
functions so Immutable Core module rules can apply to Immutable Core Models as
well.

Because Immutable Core Model access control rules are much more fine grained it
is usually best to define all access control rules at the model leve instead of
at the module level.

### Access control rules for Immutable App routes

| Rule                      |     Description                                  |
|------------------------------------------------------------------------------|
| route:/:0                 | deny access to all routes                        |
| route:/admin:0            | deny access to all routes under /admin           |
| route:/admin/auth:1       | allow access to all methods under /admin/auth    |
| route:/admin/role:get:1   | allow access to get all under /admin/role        |
| route:/admin/role:post:1  | allow access to post all under /admin/role       |
| route:/admin/role:put:1   | allow access to put all under /admin/role        |
| route:/admin/role:delete:1| allow access to delete all under /admin/role     |

Access control rules for routes can be duplicative of access control rules for
models since many routes will map directly to model actions that can have their
own access control rules defined at the model level.

It is usually best to define access control rules at the model level but
defining coarse access control rules at the route level provides an additional
safeguard against misconfigured model access control rules.

Route access control rules are evaluated earlier in the request cycle than
model access control rules so using route rules is more efficient and will
limit the amount of system resources that can be consumed by unauthorized
users.

## Creating a new Immutable Access Control instance

    var accessControl = new ImmutableAccessControl()

Immutable Access Control has a single globalton instance that will be returned
whenever `new` is called.

## Setting rules

    var accessControl = new ImmutableAccessControl()

    accessControl.setRules([
        ['all', 'model:0'],
        ['admin', 'model:1']
    ])

Calling `setRules` has the same effect as calling `new` once the initial
Immutable Access Control instance has been created.

Rules must be passed as an array of rules. Each rule must be an array of one or
more role names followed by a single access control rule.

Multiple identical access control rules can be set for different roles.

An error will be thrown on any invalid rules.