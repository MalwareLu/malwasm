/**
 * Copyright (C) 2012 Malwasm Developers.
 * This file is part of Malwasm - https://code.google.com/p/malwasm/
 * See the file LICENSE for copying permission.
 * ajax.js 
 *                  _                             
 *  _ __ ___   __ _| |_      ____ _ ___ _ __ ___  
 * | '_ ` _ \ / _` | \ \ /\ / / _` / __| '_ ` _ \ 
 * | | | | | | (_| | |\ V  V / (_| \__ \ | | | | |
 * |_| |_| |_|\__,_|_| \_/\_/ \__,_|___/_| |_| |_|
 *
 * Descriptions:
 * Malwasm models class
 */

function Models(){
	this.initialize();
}

Models.prototype = {
	initialize: function()
	{
		window.models = this;
	},
	getNbThread : function()
	{

		$.ajax({
                	type: "GET",
                	url: "nthreads?sample_id=" + malwasm.sample_id,
                	dataType: "json",
                	error: function( objRequest ){
                        	alert(objRequest.statusText);
                	},
                	success: function(data) {
                        	 view.setNThread(data);
                	}
        	});
	},
	
	setInsId: function(ins_id)
	{
		this.ins_id = ins_id;
	},
	
	setThreadId: function(thread_id)
	{
		this.thread_id = thread_id;
	},
	
	getInstructions: function(callback)
	{
		$.ajax({
                	type: "GET",
                	url: "instructions?sample_id=" + malwasm.sample_id + "&thread_id=" + malwasm.thread_id ,
	                dataType: "json",
        	        error: function( objRequest ){
                	        alert(objRequest.statusText);
	                },
        	        success: function(data) {
				        malwasm.data['instructions'] = data['instructions'];
                        malwasm.data['structures']=data['structures'];
				        callback();
                	}
        	});
	},
	
	getInfoInstruction: function(callback)
	{
		 var url = "instruction?sample_id=" + malwasm.sample_id + "&ins_id=" + malwasm.ins_id + "&thread_id=" + malwasm.thread_id;
        	$.ajax({
                	type: "GET",
                	url: url,
                	dataType: "json",
	                error: function( objRequest ){
	                        alert(objRequest.statusText);
	                },
	                success: callback
        	});
	},
	getSamplesList : function()
	{
		var url = "samples"
		
		var sampleListRequest = $.ajax({
			type: "GET",
			url: url,
			dataType: "json",
			error: function( objRequest ){
				alert(objRequest.statusText);
			},
			success: function(data) {
				view.displaySamplesList(data);
			}
		});

	},

	loadInfoMemByType: function( dump_type, callback)
	{
		var url = "dumpInfo?sample_id=" + malwasm.sample_id 
                + "&ins_id=" + malwasm.ins_id 
                + "&thread_id=" + malwasm.thread_id
         	    + "&dump_type=" + dump_type;

	        $.ajax({
	                type: "GET",
	                url: url,
	                dataType: "json",
	                error: function( objRequest ){
	                        alert(objRequest.statusText);
	                },
	                success: callback
        	});
	},
	loadMemByRange: function( adr_start, adr_stop, callback)
	{
		if (adr_start == -1 || adr_stop == -1 || adr_start > adr_stop)
        {
            console.log("adr_start: "+adr_start+" | adr_stop: "+adr_stop);
            throw "Load memory parameter error";
        }
        var url = "dump?sample_id=" + malwasm.sample_id 
                + "&ins_id=" + malwasm.ins_id
                + "&thread_id=" + malwasm.thread_id
	            + "&start=" + adr_start
                + "&stop=" + adr_stop;
	
	    var xhr = new XMLHttpRequest();
	    xhr.open("GET", url, true);
	    xhr.responseType = "arraybuffer";
	    xhr.onload = callback;
		xhr.send();
	},
    getMemRange: function( callback)
	{
		var url = "dumpRange?sample_id=" + malwasm.sample_id
                + "&thread_id=" + malwasm.thread_id;

	        $.ajax({
	                type: "GET",
	                url: url,
	                dataType: "json",
	                error: function( objRequest ){
	                        alert(objRequest.statusText);
	                },
	                success: callback
        	});
	}
}
