# Modified from:
# https://github.com/srunnels/broselytize/tree/master/Logging%20Youtube%20V

module Titles;

global title_set: set[string];

export {
    redef enum Log::ID += { LOG };

    type Info: record {
		ts:			time	&log;
		title:		string	&log;
        };
    }

event bro_init()
    {
    Log::create_stream(LOG, [$columns=Info]);
    }
 
event http_reply(c: connection, version: string, code: count, reason: string)
    {
    if ( c$http$method == "GET" )
        {
        add title_set[c$uid];
        }
    }
    

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( is_orig )
        {
        return;
        }

    if ( c$uid in title_set )
        {
                
        if ( /\<title\>/ in data && /\<\/title\>/ in data )
            {

   		 # find title tags
            local temp: table[count] of string;
   		 temp = split(data, /\<\/?title\>/);

            if ( 2 in temp )
            {
				Log::write( Titles::LOG, [$ts=network_time(),
										  $title=temp[2]] );
            }
            delete title_set[c$uid];
            }
        }
    }
