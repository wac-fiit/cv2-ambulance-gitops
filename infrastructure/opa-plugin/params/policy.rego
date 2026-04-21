package wac.authz
import input.attributes.request.http as http_request

# Define allowed emails
allowed_emails := {"michal.sevcik@protonmail.com", "example@email.com"}

default allow = false

# define authenticated user
is_valid_user = true if { http_request.headers["x-forwarded-email"] }

user = { "valid": valid, "email": email, "name": name} if {
    valid := is_valid_user
    email := http_request.headers["x-forwarded-email"]
    name := http_request.headers["x-forwarded-user"]
}

# allow access if user is authenticated and email is in allowed list
allow if {
    user.valid
    user.email in allowed_emails
}

# set header to indicate that this policy was used to validate the request
headers["x-validated-by"] := "opa-checkpoint"

# provide result to caller
result["allowed"] := allow