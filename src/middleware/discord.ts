import { MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import { nanoid } from "nanoid";
import { Jwt } from "hono/utils/jwt";
import { AlgorithmTypes } from "hono/utils/jwt/types";
import { z } from "zod";
import { APIUser } from "discord-api-types/v10";

const initialQueryScheme = z.object({
	redirect: z.string().optional()
});

const callbackQueryScheme = z.object({
	code: z.string(),
	state: z.string().optional()
});

export interface DiscordTokenRes {
	access_token: string;
	token_type: "Bearer";
	expires_in: number;
	expires_at: number;
	refresh_token: string;
	scope: string;
}

export interface StateData {
	redirect?: string;
	customStateData?: any;
}

export interface Options {
	clientId: string;
	clientSecret: string;
	/** 
	 * URL for discord to redirect back to (this must be middleware whereever that is)
	 * Can be same as this url
	 */
	callbackUrl: string;
	/**
	 * Default redirect after auth, optional
	 */
	redirectUrl?: string;
	/**
	 * Scopes to request
	 */
	scope: string[];
	/**
	 * Whether to use states (required for redirect)
	 */
	useState?: boolean;
	/**
	 * if you want to carry over any custom data for this user (internal ID, etc.), provide it here
	 */
	customStateData?: any;
	/**
	 * Store state data for this middleware
	 * @param state state ID
	 * @param data data to store
	 */
	stateStorageAdd?: (state: string, data: StateData) => Promise<void>;
	/**
	 * Get state data for this middleware
	 * @param state state ID
	 */
	stateStorageGet?: (state: string) => Promise<StateData>;
	/**
	 * Allow this middleware to delete state data after use.
	 * You should also have an internal system to remove old state data (cron job or something)
	 * @param state
	 */
	stateStorageDelete?: (state: string) => Promise<void>;
	/**
	 * Middleware will call this function to give you the user's data (if enabled) and token result
	 * @param tokenRes 
	 * @param userData 
	 * @param customStateData 
	 * @returns 
	 */
	saveTokenRes: (tokenRes: DiscordTokenRes, userData?: APIUser, customStateData?: any) => Promise<void>;
	/**
	 * Secret for JWT state. Leave undefined if you do not want to use JWT for state data
	 * NOTE: If using this do not store sensitive data in custom state data
	 */
	jwtSecret?: string;
	// Only allow to same site ("/") or certain domains ("https://example.com")
	// default to same site
	/**
	 * Array of prefixes for permitted urls to redirect to (can enforce https with this)
	 * @example ["https://mysite.com", "https://api.myapi.com", "/"]
	 * @default ["/"]
	 */
	validRedirectPrefixes?: string[];
	/**
	 * Will check if authorized still and refresh token if needed.
	 * Provide this function for the middleware to fetch old token results (must be in format this middleware provided)
	 * Default is disabled
	 */
	getPastTokenRes?: () => Promise<DiscordTokenRes>;
	/**
	 * If enabled, will fetch user data from discord and provide it to {@link DiscordOptions.saveTokenRes}
	 * @default true
	 */
	fetchUserData?: boolean;
	/**
	 * Will attempt a fetch user to check if user is still authorized
	 * Prevents issues if they deauthorize in Discord settings, you can handle this elsewhere in your app though
	 * @default false
	 */
	fetchUserDataOnCheck?: boolean;
	/**
	 * Check if granted scopes are what you want
	 * @default true
	 */
	checkScopes?: boolean;
	/**
	 * How long for the JWT state to be valid for (in seconds) if using JWT
	 * Default is 5 mins
	 * @default 300
	 */
	jwtStateLifetime?: number;
}

export const discordOauth = (options: Options): MiddlewareHandler => {
	if (options.useState == undefined) options.useState = true;
	if (options.validRedirectPrefixes == undefined) options.validRedirectPrefixes = ["/"];
	if (options.fetchUserData == undefined) options.fetchUserData = true;
	if (options.fetchUserDataOnCheck == undefined) options.fetchUserDataOnCheck = false;
	if (options.checkScopes == undefined) options.checkScopes = true;
	if (options.jwtStateLifetime == undefined) options.jwtStateLifetime = 60 * 5;

	const fetchUserData = async (tokenResult: DiscordTokenRes): Promise<APIUser> => {
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
	
	const checkValidRedirect = (validStartsWith: string[], checkString: string) => {
		let valid = false;
		validStartsWith.forEach(prefix => {
			if (checkString.startsWith(prefix)) valid = true;
		});
		return valid;
	};

	return async (c, next) => {
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
					} else {
						let authorized = true;
						if (options.fetchUserDataOnCheck) {
							try {
								await fetchUserData(pastTokenRes);
							}
							catch (e) { // reauthorize
								authorized = false;
							}
						}
						if (authorized) return await next();
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
					throw new HTTPException(403, {message: "Scopes modified, try again"});
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
				} else if (options.jwtSecret) { // use jwt
					if (await Jwt.verify(state, options.jwtSecret, AlgorithmTypes.HS256).catch(() => {return;})) {
						stateData = Jwt.decode(state).payload;
					}
				}
				if (!stateData) {
					throw new HTTPException(403, {message: "Invalid state (probably expired, try again)"});
				}
				if (options.stateStorageDelete) { // delete
					options.stateStorageDelete(state);
				}
				await options.saveTokenRes(tokenResult, userData, stateData.customStateData); // save data
				if (stateData.redirect) {
					return c.redirect(stateData.redirect);
				}
			} else {
				await options.saveTokenRes(tokenResult, userData, undefined); // save data
			}

			await next(); // continue
		} else if (initialQueryData.success) { // initial call
			const redirect = initialQueryData.data.redirect ?? options.redirectUrl;
			if (redirect) {
				if (!checkValidRedirect(options.validRedirectPrefixes!, redirect)) {
					throw new HTTPException(400, {message: "Invalid redirect url"});
				}
			}

			let state;
			if (options.useState) {
				if (options.stateStorageAdd) { // use state storage
					const state = nanoid(8);
					await options.stateStorageAdd(state, {
						redirect,
						customStateData: options.customStateData
					});
				}
				else if (options.jwtSecret) { // use jwt
					state = await Jwt.sign({
						exp: Math.floor(Date.now() / 1000) + options.jwtStateLifetime!, // state lifetime
						redirect,
						customStateData: options.customStateData
					}, options.jwtSecret, AlgorithmTypes.HS256);
				}
				// redirect
			}
			
			const url = new URL("https://discord.com/api/oauth2/authorize");
			url.searchParams.set("client_id", options.clientId);
			url.searchParams.set("redirect_uri", options.callbackUrl);
			url.searchParams.set("response_type", "code");
			url.searchParams.set("scope", options.scope.join(" "));
			if (state) url.searchParams.set("state", state);
			return c.redirect(url.toString());
		} else {
			throw new HTTPException(400, {message: "Invalid query parameters"});
		}
	};
};