package authn

type JwtMiddlewareOpt func(mw *JwtMiddleware) *JwtMiddleware

// RequireAuth will cause the middleware to respond with 401 if no auth token is present.
// This is the opposite of IgnoreMissingAuth.
func RequireAuth() JwtMiddlewareOpt {
	return func(mw *JwtMiddleware) *JwtMiddleware {
		mw.requireAuth = true
		return mw
	}
}

// IgnoreMissingAuth will cause the middleware to forward the request to the next handler if no auth token is present.
// This is the opposite of RequireAuth.
func IgnoreMissingAuth() JwtMiddlewareOpt {
	return func(mw *JwtMiddleware) *JwtMiddleware {
		mw.requireAuth = false
		return mw
	}
}
