[![Build
status](https://travis-ci.org/dbca-wa/authome.svg?branch=master)](https://travis-ci.org/dbca-wa/authome/builds) [![Coverage Status](https://coveralls.io/repos/github/dbca-wa/authome/badge.svg?branch=master)](https://coveralls.io/github/dbca-wa/authome?branch=master)

# authome

HTTP service for single sign-on session tracking authenticated against Microsoft Azure AD.

## How it works
Authome acts like middleware for a proxy server, and behaves as a single application to a third party (in this case only Azure AD), that then injects authentication headers and an authentication suburl `/sso/auth`. As long as your network is secure between nginx and your backend app server, this can be used for easy serverside authentication by trusting headers, and clientside authentication with a basic fetch of a suburl like so:
```javascript
fetch('/sso/auth').then(response => response.json()).then(window.identity => data);
```

## Nginx config for an authome client
    # nginx.conf client section
    server {
        server_name     ...;
        # listen config ...
        location /sso {
            uwsgi_pass_request_headers off;
            uwsgi_param  HTTP_AUTHORIZATION $http_authorization;
            uwsgi_param  HTTP_COOKIE        $http_cookie;

            uwsgi_param  QUERY_STRING       $query_string;
            uwsgi_param  REQUEST_METHOD     $request_method;

            uwsgi_param  REQUEST_URI        $request_uri;
            uwsgi_param  PATH_INFO          $document_uri;
            uwsgi_param  DOCUMENT_ROOT      $document_root;
            uwsgi_param  SERVER_PROTOCOL    $server_protocol;
            uwsgi_param  HTTPS              $https if_not_empty;

            uwsgi_param  REMOTE_ADDR        $remote_addr;
            uwsgi_param  REMOTE_PORT        $remote_port;
            uwsgi_param  SERVER_PORT        $server_port;
            uwsgi_param  SERVER_NAME        'authome-test.example.com';
            uwsgi_param  HTTP_X_UPSTREAM_SERVER_NAME        $server_name;

            uwsgi_pass authome_dbca;
        }
        set $authome_redirect https://authome-test.example.com/?next=$host$request_uri;
        set $authome_logout https://authome-test.example.com/sso/auth_logout;

        location / {
            auth_request /sso/auth;
            auth_request_set $username $upstream_http_x_username;
            proxy_set_header remote-user $username;
            auth_request_set $setcookie $upstream_http_set_cookie;
            proxy_set_header set-cookie $setcookie;
            auth_request_set $email $upstream_http_x_email;
            proxy_set_header X-email $email;
            auth_request_set $firstname $upstream_http_x_first_name;
            proxy_set_header X-first-name $firstname;
            auth_request_set $lastname $upstream_http_x_last_name;
            proxy_set_header X-last-name $lastname;
            auth_request_set $fullname $upstream_http_x_full_name;
            proxy_set_header X-full-name $fullname;
            auth_request_set $sharedid $upstream_http_x_shared_id;
            proxy_set_header X-shared-id $sharedid;
            auth_request_set $logouturl $upstream_http_x_logout_url;
            proxy_set_header X-logout-url $logouturl;
            auth_request_set $sessionkey $upstream_http_x_session_key;
            proxy_set_header X-session-key $sessionkey;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            error_page 401 $authome_redirect;
            proxy_pass http://my.app.server;
        }

    }
## Nginx config for an authome identity server 
    # nginx.conf server section

    http {
        upstream authome_test {
            ip_hash;
            server 192.168.1.1:8080;
            server 192.168.2.1:8080;
        }

        server {
            server_name     authome-test.example.com
            include         listen/https_noauth;
            include         custom/authome_uat_auth_location;

            location / {
                include uwsgi_params;
                uwsgi_pass authome_test;
            }
        }

    }

    # uwsgi_params
    uwsgi_param  QUERY_STRING       $query_string;
    uwsgi_param  REQUEST_METHOD     $request_method;
    uwsgi_param  CONTENT_TYPE       $content_type;
    uwsgi_param  CONTENT_LENGTH     $content_length;

    uwsgi_param  REQUEST_URI        $request_uri;
    uwsgi_param  PATH_INFO          $document_uri;
    uwsgi_param  DOCUMENT_ROOT      $document_root;
    uwsgi_param  SERVER_PROTOCOL    $server_protocol;
    uwsgi_param  HTTPS              $https if_not_empty;

    uwsgi_param  REMOTE_ADDR        $remote_addr;
    uwsgi_param  REMOTE_PORT        $remote_port;
    uwsgi_param  SERVER_PORT        $server_port;
    uwsgi_param  SERVER_NAME        $server_name;
    

