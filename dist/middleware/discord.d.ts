import { MiddlewareHandler } from "hono";
import { APIUser } from "discord-api-types/v10";
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
    getPastTokenRes?: () => Promise<DiscordTokenRes | undefined>;
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
export declare const discordOauth: (options: Options) => MiddlewareHandler;
