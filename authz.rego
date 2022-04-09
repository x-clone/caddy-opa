package system.authz

default allow = false

allow {
	input.method == "GET"
	input.identity == "mytoken"
}
