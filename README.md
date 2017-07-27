[![Build
status](https://travis-ci.org/parksandwildlife/authome.svg?branch=master)](https://travis-ci.org/parksandwildlife/authome/builds) [![Coverage Status](https://coveralls.io/repos/github/parksandwildlife/authome/badge.svg?branch=master)](https://coveralls.io/github/parksandwildlife/authome?branch=master)

# authome

HTTP service for single sign-on session tracking authenticated against Microsoft Azure AD.

## How it works


## Example nginx config
    # nginx.conf

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
    

