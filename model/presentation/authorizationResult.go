package presentation

type AuthorizeResult struct {
	State                  string
	OpenID4VPURL           string
	RequestURI             string
	RequestURIAuthorizeURL string
}
