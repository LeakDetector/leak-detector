module cookie;
export {
    redef enum Log::ID += { LOG };

    type Info: record {
		ts:			time	&log;
		cookie:		string	&log &optional;
		host:		string	&log;
        };
	
}
event bro_init()
{
    Log::create_stream(LOG, [$columns=Info]);
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
		# Grab cookies with URI
    if ( is_orig && name == "COOKIE" )
		Log::write( cookie::LOG, [$ts=network_time(),
											$cookie=value,
											$host=c$http$host]);
}