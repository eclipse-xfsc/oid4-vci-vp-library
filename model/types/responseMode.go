package types

type ResponseMode string

const (
	DirectPost    ResponseMode = "direct_post"
	DirectPostJwt ResponseMode = "direct_post.jwt"
	Fragment      ResponseMode = "fragment"
)
