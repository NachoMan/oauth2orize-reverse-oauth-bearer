/**
 * Module dependencies.
 */
var utils = require('./utils'),
    request = require('request'),
    AuthorizationError = require('./errors/authorizationerror');


module.exports = function reverseOAuthBearer(options, issue) {
    if (typeof options == 'function') {
        issue = options;
        options = null;
    }
    options = options || {};

    if (!issue)
        throw new Error('OAuth 2.0 Reverse OAuth exchange middleware requires an issue function.');

    var userProperty = options.userProperty || 'user';

    return function reverse_bearer(req, res, next) {
        if (!req.body)
            return next(new Error('Request body not parsed. Use bodyParser middleware.'));
        if (!req.body.assertion)
            return next(new AuthorizationError('missing assertion parameter', 'invalid_request'));

        var client = req[userProperty];
        var contents = JSON.parse(req.body.assertion);

        function issued(err, accessToken, refreshToken, params) {
            if (err) { return next(err); }
            if (!accessToken) { return next(new AuthorizationError('invalid access token', 'invalid_grant')); }
            if (!refreshToken)
                refreshToken = params;

            var tok = {};
            tok['access_token'] = accessToken;
            if (refreshToken)
                tok['refresh_token'] = refreshToken;
            if (params)
                utils.merge(tok, params);
            tok['token_type'] = tok['token_type'] || 'bearer';

            var json = JSON.stringify(tok);
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Cache-Control', 'no-store');
            res.setHeader('Pragma', 'no-cache');
            res.end(json);
        }

        issue(client, contents, issued);
    }
}
