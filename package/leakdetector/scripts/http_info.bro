module http_info;

redef HTTP::default_capture_password = T;


export {
    redef enum Log::ID += { LOG };

    type Info: record {
		ts:			time	&log;
		host:		string	&log;
		uri:		string 	&log;
        };
	
}

event bro_init()
{
    Log::create_stream(LOG, [$columns=Info]);
}

																		
#event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) 
event http_reply(c: connection, version: string, code: count, reason: string)
{
	if ( c$http$method == "GET" ) 
		Log::write( http_info::LOG, [$ts=network_time(),										
											$host=c$http$host,
											$uri=c$http$uri]);	
}