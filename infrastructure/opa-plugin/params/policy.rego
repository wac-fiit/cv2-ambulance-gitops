package wac.authz
import input.attributes.request.http as http_request

# Define authenticated user
is_valid_user = true if { http_request.headers["x-forwarded-email"] }

user = { "valid": valid, "email": email, "name": name} if {
    valid := is_valid_user
    email := http_request.headers["x-forwarded-email"]
    name := http_request.headers["x-forwarded-user"]
}

default allow = false

# allow access if user is authenticated with a valid email
allow if {
    user.valid
}

# set header to indicate that this policy was used to validate the request
headers["x-validated-by"] := "opa-checkpoint"

# provide result to caller
result["allowed"] := allow