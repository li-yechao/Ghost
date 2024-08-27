const models = require('../../../models');

function SessionMiddleware({sessionService}) {
    async function createSession(req, res, next) {
        try {
            await sessionService.createSessionForUser(req, res, req.user);
            res.sendStatus(201);
        } catch (err) {
            next(err);
        }
    }

    async function destroySession(req, res, next) {
        try {
            await sessionService.destroyCurrentSession(req);
            res.sendStatus(204);
        } catch (err) {
            next(err);
        }
    }

    const blockletGhostRolesMap = {
        owner: 'Owner',
        admin: 'Administrator',
        member: 'Author'
    };

    async function authenticate(req, res, next) {
        try {
            let user;

            const did = req.get('x-user-did');
            if (did) {
                const fullName = req.get('x-user-fullname');
                const email = req.get('x-user-email');

                const role = req.get('x-user-role');
                const ghostRoleName = blockletGhostRolesMap[role];

                const ghostRole = ghostRoleName ? await models.Role.findOne({name: ghostRoleName}) : undefined;
                const ghostRoleId = ghostRole?.id;

                user = await models.User.findOne({did});
                if (!user) {
                    user = await models.User.add({
                        did,
                        name: fullName,
                        email,
                        password: did,
                        blogTitle: fullName,
                        roles: ghostRoleId ? [ghostRoleId] : [],
                        status: 'active'
                    });
                } else {
                    if (user.attributes.name !== fullName || user.attributes.email !== email) {
                        user = await models.User.edit({
                            did,
                            name: fullName,
                            email
                        }, {
                            id: user.id
                        });
                    }

                    const roles = await user.roles().fetch();

                    if (roles.models[0]?.attributes.name !== ghostRoleName) {
                        if (ghostRoleId) {
                            if (roles.models.length) {
                                await user.roles().updatePivot({role_id: ghostRoleId});
                            } else {
                                await user.roles().attach({id: models.User.generateId(), role_id: ghostRoleId});
                            }
                        } else {
                            for (const i of roles.models) {
                                await user.roles().detach(i);
                            }
                        }
                    }
                }
            }

            // const user = await sessionService.getUserForSession(req, res);
            if (user) {
                // Do not nullify `req.user` as it might have been already set
                // in a previous middleware (authorize middleware).
                req.user = user;
            }
            next();
        } catch (err) {
            next(err);
        }
    }

    return {
        createSession: createSession,
        destroySession: destroySession,
        authenticate: authenticate
    };
}

module.exports = SessionMiddleware;
