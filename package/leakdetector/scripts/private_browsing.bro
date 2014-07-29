module private_browsing;

# to keep track of which connections just issued an HTTP get
global get_set: set[string];

# to keep track of conns on which we've seen a request with no cookie
global no_cookie_get_set: set[string];
global no_cookie_reply_set: set[string];

export {
    redef enum Log::ID += { LOG };

    type Info: record {
		ts:			time	&log;
		host:		string	&log;
		uri:		string	&log;
        };
    }

event bro_init()
    {
    Log::create_stream(LOG, [$columns=Info]);
    }


# Take note of new GET requests so we can look at the headers once they're parsed
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    if ( c$http$method == "GET" )
        {
        add get_set[c$uid];
        }
    }

# if the GET had no cookie, mark the beginning of the reply
event http_reply(c: connection, version: string, code: count, reason: string)
    {

    if ( c$http$method == "GET" && c$uid in no_cookie_get_set )
        {
        	add no_cookie_reply_set[c$uid];
			delete no_cookie_get_set[c$uid];
        }
    }
 
event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
		# If this is a GET, check if it has a COOKIE header; mark it if not
		if ( c$uid in get_set ) {
			local found_cookie:bool = F;
			for ( k in hlist ) {
				if (hlist[k]$name == "COOKIE") {
					found_cookie = T;
				}
			}
			if (!found_cookie) {
				add no_cookie_get_set[c$uid];
			}

			delete get_set[c$uid];
		}

		# if this is the beginning of a reply whose GET had no cookie, check to
		# see if there's a SET-COOKIE header; if so, this may indicate that
		# the GET was made in private browsing mode
		if ( c$uid in no_cookie_reply_set ) {
			local found_set_cookie:bool = F;
			for ( k in hlist ) {
				if (hlist[k]$name == "SET-COOKIE") {
					found_set_cookie = T;
				}
			}
			if (found_set_cookie) {
				Log::write( private_browsing::LOG, [$ts=network_time(),
													$host=c$http$host,
													$uri=c$http$uri]);
			}

			delete no_cookie_reply_set[c$uid];
		}

    }
