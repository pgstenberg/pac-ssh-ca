package ssh.authz

import rego.v1

default allow := false

default validprincipals := []
default extensions := {}
default criticaloptions := {}
default validafter := 0
default validbefore := 0

allow if {
    "user" in input.aud
    input.sub == input.state.sub
    input.sub == input.username
    input.fingerprint == input.state.fingerprint
}
allow if {
    "host" in input.aud
    input.sub == input.addr
    input.sub == input.username
}

validprincipals = [
	input.sub
] if allow

validafter = input.nbf if allow
validbefore = input.exp if allow

extensions = {
	"permit-X11-forwarding":   "",
	"permit-agent-forwarding": "",
	"permit-port-forwarding":  "",
	"permit-pty":              "",
	"permit-user-rc":          "",
} if {
    allow
    "user" in input.aud
}