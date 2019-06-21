when HTTP_REQUEST {
    HTTP::header remove X-Authenticated-User
    HTTP::header remove X-Authenticated-Groups
}