/**
 * Copyright (C) 2012 Malwasm Developers.
 * This file is part of Malwasm - https://code.google.com/p/malwasm/
 * See the file LICENSE for copying permission.
 * dialog.samples.js 
 *                  _                             
 *  _ __ ___   __ _| |_      ____ _ ___ _ __ ___  
 * | '_ ` _ \ / _` | \ \ /\ / / _` / __| '_ ` _ \ 
 * | | | | | | (_| | |\ V  V / (_| \__ \ | | | | |
 * |_| |_| |_|\__,_|_| \_/\_/ \__,_|___/_| |_| |_|
 *
 * Descriptions:
 * Manage the samples dialog
 */

/**
 * Init the samples selection dialog
 */
function initSamplesDialog(){
	$( "#dialog-samples" ).dialog({
		autoOpen: true,
		height: 400,
		width: 650,
		modal: true,
		open: loadSamplesList()
	});
}

/**
 * Load and display the samples list with a ajax call
 */
function loadSamplesList(){

	var url = "samples"
	
	$.ajax({
		type: "GET",
		url: url,
		dataType: "json",
		error: function( objRequest ){
			alert(objRequest.statusText);
		},
		success: function(data) {
			$("#samples tbody tr").remove();

			for(r in data){
				s = data[r];

				t = "<tr id='sample_{0}'>" +
					"<td><a onclick='loadSample({0})'><img src='static/images/download.png'</a></td>" +
					"<td>{1}</td>" +
					"<td>{2}</td>" +
					"<td>{3}</td>" +
					"<td>{4}</td>" +
					"<td>{5}</td>" +
					"</tr>"

				t = t.format(s.id, s.id, s.md5, s.filename, s.pin_param, s.insert_at)

				$("#samples tbody").append(t);
			}
		}
	});

}

/**
 * Close the sample dialog and init the loading of the data
 *
 * Parameters:
 * (int) id - the sample id we want to load
 *
 * Globals:
 * (int) sample_id - save the new sample_id
 */
function loadSample(id){
	$("#dialog-samples").dialog("close");
	$("#sample_id").text(id);
	var t = $("#sample_"+id+" td:nth-child(3)").text();
	$("#sample_hash").html(t);
	var t = $("#sample_"+id+" td:nth-child(4)").text();
	$("#sample_filename").text(t);
	var t = $("#sample_"+id+" td:nth-child(6)").text()
	$("#sample_date").text(t);
	sample_id= id;
	loadThreadsNumbers(id);
}
