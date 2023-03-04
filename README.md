Use as middleware with Hono to authorize Discord.

If you wish to use your context you can call this middleware inside another middleware like this:

```js
app.use("/blah", async (c, next) => {
	return discordOauth({/*options using context*/})(c, next);
});
```