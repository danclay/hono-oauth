"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.discordOauth = void 0;
const nanoid_1 = require("nanoid");
const jwt_1 = require("hono/utils/jwt");
const types_1 = require("hono/utils/jwt/types");
const zod_1 = require("zod");
const initialQueryScheme = zod_1.z.object({
    redirect: zod_1.z.string().optional()
});
const callbackQueryScheme = zod_1.z.object({
    code: zod_1.z.string(),
    state: zod_1.z.string().optional()
});
const errorCbQueryScheme = zod_1.z.object({
    error: zod_1.z.string(),
    error_description: zod_1.z.string().optional()
});
const discordOauth = (options) => {
    if (options.useState == undefined)
        options.useState = true;
    if (options.validRedirectPrefixes == undefined)
        options.validRedirectPrefixes = ["/"];
    if (options.fetchUserData == undefined)
        options.fetchUserData = true;
    if (options.fetchUserDataOnCheck == undefined)
        options.fetchUserDataOnCheck = false;
    if (options.checkScopes == undefined)
        options.checkScopes = true;
    if (options.jwtStateLifetime == undefined)
        options.jwtStateLifetime = 60 * 5;
    const fetchUserData = async (tokenResult) => {
        const headers = new Headers();
        headers.append("Authorization", tokenResult.token_type + " " + tokenResult.access_token);
        const requestOptions = {
            method: "GET",
            headers
        };
        const response = await fetch("https://discord.com/api/v10/users/@me", requestOptions)
            .catch(error => {
            throw new Error(error);
        });
        const result = await response.json();
        return result;
    };
    const checkValidRedirect = (validStartsWith, checkString) => {
        let valid = false;
        validStartsWith.forEach(prefix => {
            if (checkString.startsWith(prefix))
                valid = true;
        });
        return valid;
    };
    return async (c, next) => {
        var _a;
        const query = c.req.query();
        const initialQueryData = initialQueryScheme.safeParse(query);
        const callbackQueryData = callbackQueryScheme.safeParse(query);
        const errorCbQueryData = errorCbQueryScheme.safeParse(query);
        if (callbackQueryData.success) { // callback (comes first due to query params)
            const code = callbackQueryData.data.code;
            const state = callbackQueryData.data.state;
            const headers = new Headers();
            headers.append("Content-Type", "application/x-www-form-urlencoded");
            const urlencoded = new URLSearchParams();
            urlencoded.append("client_id", options.clientId);
            urlencoded.append("client_secret", options.clientSecret);
            urlencoded.append("grant_type", "authorization_code");
            urlencoded.append("code", code);
            urlencoded.append("redirect_uri", options.callbackUrl);
            const requestOptions = {
                method: "POST",
                headers,
                body: urlencoded
            };
            const response = await fetch("https://discord.com/api/v10/oauth2/token", requestOptions)
                .catch(error => {
                throw new Error(error);
            });
            const tokenResult = await response.json();
            if (tokenResult.error) { // invalid code
                return c.text("401: " + tokenResult.error, 401);
            }
            // verify scopes
            if (options.checkScopes) {
                const resultScope = tokenResult.scope.split(" ");
                const filtered = options.scope.filter(scope => resultScope.includes(scope));
                if (filtered.length != options.scope.length) {
                    return c.text("403: Scopes modified, try again", 403);
                }
            }
            tokenResult.expires_at = Math.floor(Date.now() / 1000) + tokenResult.expires_in;
            let userData;
            if (options.fetchUserData) {
                userData = await fetchUserData(tokenResult);
            }
            if (state) {
                let stateData;
                if (options.stateStorageGet) {
                    stateData = await options.stateStorageGet(state);
                }
                else if (options.jwtSecret) { // use jwt
                    if (await jwt_1.Jwt.verify(state, options.jwtSecret, types_1.AlgorithmTypes.HS256).catch(() => { return; })) {
                        stateData = jwt_1.Jwt.decode(state).payload;
                    }
                }
                if (!stateData) {
                    return c.text("403: Invalid state (probably expired, try again)", 403);
                }
                if (options.stateStorageDelete) { // delete
                    options.stateStorageDelete(state);
                }
                await options.saveTokenRes(tokenResult, userData, stateData.customStateData); // save data
                if (stateData.redirect) {
                    return c.redirect(stateData.redirect);
                }
            }
            else {
                await options.saveTokenRes(tokenResult, userData, undefined); // save data
            }
            await next(); // continue
        }
        else if (errorCbQueryData.success) { // if error
            return c.text("401: " + errorCbQueryData.data.error, 401);
        }
        else if (initialQueryData.success) { // initial call
            const redirect = (_a = initialQueryData.data.redirect) !== null && _a !== void 0 ? _a : options.redirectUrl;
            if (redirect) {
                if (!checkValidRedirect(options.validRedirectPrefixes, redirect)) {
                    return c.text("400: Invalid redirect url", 400);
                }
            }
            // check if already authorized
            if (options.getPastTokenRes) {
                const pastTokenRes = await options.getPastTokenRes();
                if (pastTokenRes) {
                    if (pastTokenRes.expires_at > Math.floor(Date.now() / 1000)) { // not expired
                        if (pastTokenRes.expires_at - 24 * 60 * 60 < Math.floor(Date.now() / 1000)) { // expires soon
                            // refresh token
                            const headers = new Headers();
                            headers.append("Content-Type", "application/x-www-form-urlencoded");
                            const urlencoded = new URLSearchParams();
                            urlencoded.append("client_id", options.clientId);
                            urlencoded.append("client_secret", options.clientSecret);
                            urlencoded.append("grant_type", "refresh_token");
                            urlencoded.append("code", pastTokenRes.refresh_token);
                            const requestOptions = {
                                method: "POST",
                                headers,
                                body: urlencoded
                            };
                            const response = await fetch("https://discord.com/api/v10/oauth2/token", requestOptions)
                                .catch(error => {
                                throw new Error(error);
                            });
                            const tokenResult = await response.json();
                            if (!tokenResult.error) {
                                options.saveTokenRes(tokenResult);
                                if (redirect) {
                                    return c.redirect(redirect);
                                }
                                else {
                                    return await next();
                                }
                            }
                        }
                        else {
                            let authorized = true;
                            if (options.fetchUserDataOnCheck) {
                                try {
                                    await fetchUserData(pastTokenRes);
                                }
                                catch (e) { // reauthorize
                                    authorized = false;
                                }
                            }
                            if (authorized) {
                                if (redirect) {
                                    return c.redirect(redirect);
                                }
                                else {
                                    return await next();
                                }
                            }
                        }
                    }
                }
            }
            // continue if unauthorized
            let state;
            if (options.useState) {
                if (options.stateStorageAdd) { // use state storage
                    const state = (0, nanoid_1.nanoid)(8);
                    await options.stateStorageAdd(state, {
                        redirect,
                        customStateData: options.customStateData
                    });
                }
                else if (options.jwtSecret) { // use jwt
                    state = await jwt_1.Jwt.sign({
                        exp: Math.floor(Date.now() / 1000) + options.jwtStateLifetime,
                        redirect,
                        customStateData: options.customStateData
                    }, options.jwtSecret, types_1.AlgorithmTypes.HS256);
                }
                // redirect
            }
            const url = new URL("https://discord.com/api/oauth2/authorize");
            url.searchParams.set("client_id", options.clientId);
            url.searchParams.set("redirect_uri", options.callbackUrl);
            url.searchParams.set("response_type", "code");
            url.searchParams.set("scope", options.scope.join(" "));
            if (state)
                url.searchParams.set("state", state);
            return c.redirect(url.toString());
        }
        else {
            return c.text("400: Invalid query parameters", 400);
        }
    };
};
exports.discordOauth = discordOauth;
//# sourceMappingURL=discord.js.map