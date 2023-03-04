"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.discordOauth = void 0;
const http_exception_1 = require("hono/http-exception");
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
        // check if authorized
        if (options.getPastTokenRes) {
            const pastTokenRes = await options.getPastTokenRes();
            if (pastTokenRes) {
                if (pastTokenRes.expires_at < (Date.now() / 1000)) { // not expired
                    if (pastTokenRes.expires_at - 60e6 * 24 < (Date.now() / 1000)) { // expires soon
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
                        options.saveTokenRes(tokenResult);
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
                        if (authorized)
                            return await next();
                    }
                }
            }
        }
        // continue if expired
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
            // verify scopes
            if (options.checkScopes) {
                const resultScope = tokenResult.scope.split(" ");
                const filtered = options.scope.filter(scope => resultScope.includes(scope));
                if (filtered.length != options.scope.length) {
                    throw new http_exception_1.HTTPException(403, { message: "Scopes modified, try again" });
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
                    throw new http_exception_1.HTTPException(403, { message: "Invalid state (probably expired, try again)" });
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
        else if (initialQueryData.success) { // initial call
            const redirect = (_a = initialQueryData.data.redirect) !== null && _a !== void 0 ? _a : options.redirectUrl;
            if (redirect) {
                if (!checkValidRedirect(options.validRedirectPrefixes, redirect)) {
                    throw new http_exception_1.HTTPException(400, { message: "Invalid redirect url" });
                }
            }
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
            throw new http_exception_1.HTTPException(400, { message: "Invalid query parameters" });
        }
    };
};
exports.discordOauth = discordOauth;
//# sourceMappingURL=discord.js.map