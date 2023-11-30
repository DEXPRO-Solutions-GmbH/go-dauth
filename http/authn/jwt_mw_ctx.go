package authn

import "context"

const (
	CtxKeyToken    = "dexp-serviceframework-access-token"
	CtxKeyTokenStr = "dexp-serviceframework-access-token-str"
)

// Deprecated: SetCtxAccessTokenStr is deprecated because it uses weakly typed parameters. Use SetCtxJwtGin instead.
func SetCtxAccessTokenStr(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, CtxKeyTokenStr, token)
}

// Deprecated: GetCtxAccessTokenStr is deprecated because it uses weakly typed parameters. Use GetCtxJwt instead.
func GetCtxAccessTokenStr(ctx context.Context) string {
	val := ctx.Value(CtxKeyTokenStr)
	if val == nil {
		return ""
	} else {
		return val.(string)
	}
}

// Deprecated: SetCtxAccessToken is deprecated because it uses weakly typed parameters. Use SetCtxJwtGin instead.
func SetCtxAccessToken(ctx context.Context, token interface{}) context.Context {
	return context.WithValue(ctx, CtxKeyToken, token)
}

// Deprecated: GetCtxAccessToken is deprecated because it uses weakly typed parameters. Use GetCtxJwt instead.
func GetCtxAccessToken(ctx context.Context) interface{} {
	val := ctx.Value(CtxKeyToken)
	if val == nil {
		return nil
	} else {
		return val
	}
}
