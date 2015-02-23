var REC_START = "start";
var REC_STOP = "stop";
var ERR = "ERR";

$("#start-recording").click(function(){
	iface = $("input[name='interface']:checked").val();
	fn = $("input[name='trace-name']").val();
	if ( !iface ) {
		ui_error("Please choose a network interface to record.");
	} else if ( !fn ) {
		ui_error("Please choose a name for your network trace.");
	} else {
		var startArgs = {
			'action': REC_START,
			'interface': iface,
			'fn': fn + ".json"
		};
		$.post("/record", startArgs, function(data){
			if ( data == REC_START ) {
				ui_start();
			} else if ( data.search(ERR) != -1 ) {
				var error = data.split(ERR + " ")[1];
				ui_error(error);
			}
		});			
	}
});

$("#stop-recording").click(function() {
	var stopArgs = {'action': REC_STOP};
	$.post("/record", stopArgs, function(data){
		if ( data.action == REC_STOP ) {
			ui_stop();
		} else if ( data.search(ERR) != -1 ) {
			var error = data.split(ERR + " ")[1];
			ui_error(error);
		}
	});
});

function updateData() {
	$.getJSON('/proc-status', function(data) {
		$.each(data.stdout, function(i, l){
			$("#stdout").append($("<span>" + l + "</span><br/>").hide().slideDown());
		});
	});
}

function ui_start() {
	recording = true;
	$("#recording-modal").foundation('reveal', 'open');
	$("#recording-modal p#message").html("Currently recording network traffic from <span>" + iface + "</span>.");
	setTimeout(updateData, 5000);
}

function ui_stop() {
	recording = false;		
	$(".when-active").slideUp(400);
	$("#recording-modal h2").html("Finished recording")
	$("#recording-modal").append("<a class='close-reveal-modal button'>&#215; Close</a>");
	setTimeout(updateData, 3000);
}

function ui_error(message) {
	$("#error-modal p").html(message);
	$("#error-modal").foundation('reveal', 'open');
}

$(document).ready(function() {
	if ( recording ) {
		iface = "an existing session";
		ui_start();
	}
})