'use strict';

// Load modules

const Boom = require('boom');
const Hoek = require('hoek');
const Joi = require('joi');
const Bounce = require('bounce');

// Declare internals

const internals = {};

module.exports = {
    pkg: require('../package.json'),
    register: (server, options) => {

        server.auth.scheme('cookie', internals.implementation);
    }
};

internals.schema = Joi.object({
    cookie: Joi.string().default('sid'),
    password: Joi.alternatives(Joi.string(), Joi.object().type(Buffer)).required(),
    ttl: Joi.number().integer().min(0).allow(null).when('keepAlive', { is: true, then: Joi.required() }),
    domain: Joi.alternatives(Joi.func(), Joi.string().allow(null)),
    path: Joi.string().default('/'),
    clearInvalid: Joi.boolean().default(false),
    keepAlive: Joi.boolean().default(false),
    isSameSite: Joi.valid('Strict', 'Lax').allow(false).default('Strict'),
    isSecure: Joi.boolean().default(true),
    isHttpOnly: Joi.boolean().default(true),
    redirectTo: Joi.alternatives(Joi.string(), Joi.func()).allow(false),
    appendNext: Joi.alternatives(Joi.string(), Joi.boolean()).default(false),
    redirectOnTry: Joi.boolean().default(true),
    validateFunc: Joi.func(),
    requestDecoratorName: Joi.string().default('cookieAuth'),
    ignoreIfDecorated: Joi.boolean().default(true)
}).required();

internals.CookieAuth = class {

    constructor(request, settings) {

        this.request = request;
        this.settings = settings;
    }

    set(session, value) {

        const { h, request, settings } = this;

        if (arguments.length > 1) {
            const key = session;
            Hoek.assert(key && typeof key === 'string', 'Invalid session key');
            session = request.auth.artifacts;
            Hoek.assert(session, 'No active session to apply key to');

            session[key] = value;
            return h.state(settings.cookie, session, settings.requestOptions(request));
        }

        Hoek.assert(session && typeof session === 'object', 'Invalid session');
        request.auth.artifacts = session;
        h.state(settings.cookie, session, settings.requestOptions(request));
    }

    clear(key) {

        const { h, request, settings } = this;

        if (arguments.length) {
            Hoek.assert(key && typeof key === 'string', 'Invalid session key');
            const session = request.auth.artifacts;
            Hoek.assert(session, 'No active session to clear key from');
            delete session[key];
            return h.state(settings.cookie, session, settings.requestOptions(request));
        }

        request.auth.artifacts = null;
        h.unstate(settings.cookie, settings.requestOptions(request));
    }

    ttl(msecs) {

        const { h, request, settings } = this;
        const session = request.auth.artifacts;
        const options = settings.requestOptions(request);
        options.ttl = msecs;
        Hoek.assert(session, 'No active session to modify ttl on');
        h.state(settings.cookie, session, options);
    }
};

internals.implementation = (server, options) => {

    const results = Joi.validate(options, internals.schema);
    Hoek.assert(!results.error, results.error);

    const settings = results.value;

    const cookieOptions = {
        encoding: 'iron',
        password: settings.password,
        isSecure: settings.isSecure,                  // Defaults to true
        path: settings.path,
        isSameSite: settings.isSameSite,
        isHttpOnly: settings.isHttpOnly,              // Defaults to true
        clearInvalid: settings.clearInvalid,
        ignoreErrors: true
    };

    if (settings.ttl) {
        cookieOptions.ttl = settings.ttl;
    }

    var dynamicDomain = null;
    if (typeof settings.domain === 'function') {
        dynamicDomain = settings.domain;
    } else if (settings.domain) {
        cookieOptions.domain = settings.domain;
    }

    if (typeof settings.appendNext === 'boolean') {
        settings.appendNext = (settings.appendNext ? 'next' : '');
    }

    settings.requestOptions = function(request) {
        var options = {};
        if (dynamicDomain) {
            options.domain = dynamicDomain(request);
        }
        return options;
    };

    server.state(settings.cookie, cookieOptions);

    const decoration = (request) => {

        return new internals.CookieAuth(request, settings);
    };

    // Check if the request object should be decorated
    const isDecorated = server.decorations.request.indexOf(settings.requestDecoratorName) >= 0;

    if (!settings.ignoreIfDecorated || !isDecorated) {
        server.decorate('request', settings.requestDecoratorName, decoration, { apply: true });
    }

    server.ext('onPreAuth', (request, h) => {

        // Used for setting and unsetting state, not for replying to request
        request[settings.requestDecoratorName].h = h;

        return h.continue;
    });

    const scheme = {
        authenticate: async (request, h) => {

            const validate = async () => {

                // Check cookie

                const session = request.state[settings.cookie];
                if (!session) {
                    return unauthenticated(Boom.unauthorized(null, 'cookie'));
                }

                if (!settings.validateFunc) {
                    if (settings.keepAlive) {
                        h.state(settings.cookie, session, settings.requestOptions(request));
                    }

                    return h.authenticated({ credentials: session, artifacts: session });
                }

                let credentials = session;

                try {
                    const result = await settings.validateFunc(request, session);

                    Hoek.assert(typeof result === 'object', 'Invalid return from validateFunc');
                    Hoek.assert(Object.prototype.hasOwnProperty.call(result, 'valid'), 'validateFunc must have valid property in return');

                    if (!result.valid) {
                        throw Boom.unauthorized(null, 'cookie');
                    }

                    credentials = result.credentials || credentials;

                    if (settings.keepAlive) {
                        h.state(settings.cookie, session, settings.requestOptions(request));
                    }

                    return h.authenticated({ credentials, artifacts: session });
                }
                catch (err) {

                    Bounce.rethrow(err, 'system');

                    if (settings.clearInvalid) {
                        h.unstate(settings.cookie, settings.requestOptions(request));
                    }

                    const unauthorized = Boom.isBoom(err) && err.typeof === Boom.unauthorized ? err : Boom.unauthorized('Invalid cookie');
                    return unauthenticated(unauthorized, { credentials, artifacts: session });
                }
            };

            const unauthenticated = (err, result) => {

                if (settings.redirectOnTry === false &&             // Defaults to true
                    request.auth.mode === 'try') {

                    return h.unauthenticated(err);
                }

                let redirectTo = settings.redirectTo;
                if (request.route.settings.plugins['hapi-auth-cookie'] &&
                    request.route.settings.plugins['hapi-auth-cookie'].redirectTo !== undefined) {

                    redirectTo = request.route.settings.plugins['hapi-auth-cookie'].redirectTo;
                }

                let uri = (typeof (redirectTo) === 'function') ? redirectTo(request) : redirectTo;

                if (!uri) {
                    return h.unauthenticated(err);
                }

                if (settings.appendNext) {
                    if (uri.indexOf('?') !== -1) {
                        uri += '&';
                    }
                    else {
                        uri += '?';
                    }

                    uri += settings.appendNext + '=' + encodeURIComponent(request.url.path);
                }

                return h.response('You are being redirected...').takeover().redirect(uri);
            };

            return await validate();
        }
    };

    return scheme;
};
