yahoo
google
bing/microsoft
facebook

nytimes
forum (ft)
	{sitename} --> vb_login_username?
cmu
reddit
	subreddits
		http://www.reddit.com/api/request_promo?srnames 
twitter


united
	account
		hdnAccountNumber = United MP #
	flight search
		http://www.united.com/web/en-US/default.aspx?$ContentInfo$Booking1$Origin$txtOrigin = flt from
		ctl00$ContentInfo$Booking1$Destination$txtDestination = flt to
		ctl00$ContentInfo$Booking1$DepDateTime$Depdate$txtDptDate = flt depart
		ctl00$ContentInfo$Booking1$RetDateTime$Retdate$txtRetDate = flt return
		ctl00$ContentInfo$Results$SearchBox$Cabinstype1$cboCabin = flt cabin
	
delta
	http://www.delta.com/predictive/dwr/call/plaincall/Predictive.getPredictiveCities.dwr?callCount = flt search
southwest
	flight search
		originAirport = flt from
		returnAirport = flt ow/rt
		destinationAirport = flt to
		outboundDateString = flt depart
		returnDateString = flt return
		filter(lambda form: "originAirport" in form.data.keys(), filter(lambda item: hasattr(item, 'formdata') and "Southwest" in item.name, l._export['history']['domains'])[0].formdata)[0].data
		
	flight results
		outboundTrip = itin
		inboundTrip = itin
		
jetblue
kayak

apple
steam

ufcu
chase
mint
barclays
amex
adp
schwab

wordpress
tumblr

amazon
ebay


