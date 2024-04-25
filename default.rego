package ssh.authz

import rego.v1

default allow := false

default validprincipals := []
default extensions := {}
default criticaloptions := {}
default validafter := 0
default validbefore := 0

id_token_payload := io.jwt.decode(input.ticket.id_token)[1]

allow if {
    input.principal == id_token_payload.sub
    input.principal == input.state.principal
}

validprincipals = [
	input.principal
] if allow

validafter = id_token_payload.nbf if allow
validbefore = id_token_payload.exp if allow

extensions = {
	"permit-X11-forwarding":   "",
	"permit-agent-forwarding": "",
	"permit-port-forwarding":  "",
	"permit-pty":              "",
	"permit-user-rc":          "",
} if allow