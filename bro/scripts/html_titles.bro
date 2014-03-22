# https://github.com/srunnels/broselytize/tree/master/Logging%20Youtube%20V

 global title_set: set[string];
 
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
			 	# get IP location
			 	local client = c$id$orig_h;
			 	local loc = lookup_location(client);

               	print fmt("%s (%s,%s,%s)", temp[2], loc$city, loc$region, loc$country_code);
             }
             delete title_set[c$uid];
             }
         }
     }
