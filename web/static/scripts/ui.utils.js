/**
 * Copyright (C) 2012 Malwasm Developers.
 * This file is part of Malwasm - https://code.google.com/p/malwasm/
 * See the file LICENSE for copying permission.
 * ui.utils.js 
 *                  _                             
 *  _ __ ___   __ _| |_      ____ _ ___ _ __ ___  
 * | '_ ` _ \ / _` | \ \ /\ / / _` / __| '_ ` _ \ 
 * | | | | | | (_| | |\ V  V / (_| \__ \ | | | | |
 * |_| |_| |_|\__,_|_| \_/\_/ \__,_|___/_| |_| |_|
 *
 * Descriptions:
 * utils functions needs by the UI to connect event or autoscroll for example.
 */


/**
 * Auto scroll function for the div #instruct_container
 *
 * Parameters:
 * (object) elem - element we want to scroll to
 */
function autoScrollInstruct(elem){
	var c_pos = $('#instruct_container').scrollTop();
	var pos = elem.offset().top - $('#instruct_container').offset().top;
	var h = $('#instruct_container').height() - 8;
	//console.log(c_pos + " " + pos + " " + h);
	if (pos > h || pos < 0){
		$('#instruct_container').scrollTop(pos + c_pos);
	}
}

/**
 * Auto scroll function for the div #instruct_ref
 *
 * Parameters:
 * (object) elem - element we want to scroll to
 */
function autoScrollReferences(elem){
	var c_pos = $('#inspector_ref').scrollTop();
	var pos = elem.offset().top - $('#inspector_ref').offset().top;
	var h = $('#inspector_ref').height();
	//console.log(c_pos + " " + pos + " " + h);
	if (pos > h || pos < 0){
		$('#inspector_ref').scrollTop(pos + c_pos);
	}
}

/**
 * Connect the event click for the references (elements with the class .ins_ref)
 */
function setClickReferences(){
	$(".ins_ref").click(function() {
		var id = $(this).attr('id').split("_")[1];
		$(".ins_ref").removeClass('selected');
		$(this).addClass('selected');
		positionTo(id);	
	});
}

/**
 * Connect the event click for the references (elements with the class .ins_ref)
 *
 * Globals:
 * (Array) data_ins -
 */
function setClickInstruct(){
	$(".instruct").click(function() {
		var eip = $(this).attr('id').split("_")[1];
		$(".instruct").removeClass('selected');
		$(this).addClass('selected');
		var v = first(data_ins[eip]).id;
		positionTo(v);	
	});
}

/**
 * Move the slide and update the interface for
 * the new instruction id
 *
 * Parameters:
 * (int) id - instruction id to slide
 */
function slideTo(id){
	positionTo(id);
}

/**
 * Set in place the keyboard shortcuts
 */
function setKeyboardShortCut(){
	$("#malwasm_body").keydown(function(e) {
		if(e.keyCode == 118){
			$('#stepin').click();
		}
		if(e.keyCode == 120){
			$('#start').click();
		}
		if(e.keyCode == 123){
			$('#pause').click();
		}
		e.stopImmediatePropagation();
	});
}

/**
 * Connect buttons event
 *
 * Globals:
 * (bool) run_progress - used to stop/start play
 * (object) cur_row - current instruction object
 */
function initButton(){
	$("#open").click( function(e) {
		loadSamplesList();
		$( "#dialog-samples" ).dialog("open");
	});
	$("#start").click( function(e) {
		if (run_progress == false){
			run_progress = true;
			playInstructions();
		}
	});
	
	$("#pause").click( function(e) {
		run_progress = false;
	});
	
	$("#stepin").click( function(e) {
		// Force to stop to play if we want to step
		run_progress = false;
		
		var v = $('#slider').slider( "value" );
		positionTo(++v);
	});
	
	// init undo function
	undo = new Array(-1,-1,-1,-1,-1);
	ins_id = 0;
	$("#undo").click(function(e){
		positionUndo();
	});

	/* Drop down to switch between stack and data dump view */
	$("#dump_select").change(function() {
		loadMemInfo(cur_row.sample_id, cur_row.id, cur_row.thread_id, $("#dump_select").val(),2)
	});
	$("#dump_group").change(function() {
                loadMemInfo(cur_row.sample_id, cur_row.id, cur_row.thread_id, $("#dump_select").val(),2)
        });
	$("#dump_nb_group_line").change(function() {
                loadMemInfo(cur_row.sample_id, cur_row.id, cur_row.thread_id, $("#dump_select").val(),2)
        });

	$('#select_thread').change(function() {
		thread_id = $('#select_thread').val()
		loadData(sample_id, thread_id)
	});
}

/**
 * Init JS design need
 * Used to fix the instruct container witdh on resize event
 */
function initDesign(){
	// Fix the instruct_container width on every resize event
	$(window).resize(function() {
		var w = $(window).width()-$('#debug_inspector').width()-1;
		$('#instruct_container').width(w);
		var h = $(window).height() - 
			$('.debug_footer').height() -
			$('#dump_container').height() -
			$('.debug_global_menu').height() -
			$('.debug_global_details').height() - 2
		$('#instruct_container').height(h);
		h = $('#debug_inspector').height() - 
			$('#debug_inspector_group1').height() - 
			$('.debug_footer').height() - 4
		$('#stack_list').height(h)
		h = $('#dump_container').height() -
		    $('#dump_header').height() -  4
		$('#dump_list').height(h)
	});

	// Trigger the resize event
	$(window).resize();
	$( "#position_selected").change(function (e){
		positionTo( $( "#position_selected").val() );
	});
	}

/**
 * Init the slider and connect the slide event
 *
 * Parameters:
 * (int) n - Number of instruction
 * (function( event, ui )) slidefunc - Function pointer to the event slide
 */
function initSlider(n, slidefunc){
	$("#slider").slider({
		value: 0,
		min: 0,
		max: n,
		step: 1,
		slide: 	slidefunc
	});
}

/**
 * Loop on instructions by increment the slider value
 */
function playInstructions () {
	if (!run_progress) return;

	setTimeout(function () {   
		if (!run_progress) return;
		
		var v = $('#slider').slider( "value" );
		positionTo(++v);

		if (v < n_ins) playInstructions();
	}, 500)
};

/**
 * Change value and set red color on change for div, span, ...
 */
function changeValue(box, newVal){
	if(box.text() != newVal){
		box.css("color", "red");
	}else{
		box.css("color", "black");
	}
	box.text(newVal)
}

//Position manager

// Intialization of position variable
ins_id = 0;

/**
 * Set a new position
 */
function positionTo(pos){
	positionPushLast(ins_id);
	positionSet(pos);
}
/**
 * Undo position
 */
function positionUndo(){
	var r = positionPopLast();
	if( r != -1){
		positionSet(r)
	}else{
		alert("I don't remember");
	}
}

/**
 * Set position
 */
function positionSet(pos){
	ins_id = pos;
	// Update UI display
	$( "#position_selected" ).val( pos );
        var slider = $( "#slider" );
	slider.slider( "value", pos );
	slider.slider('option', 'slide').call(slider);
	// Update instruction information
        loadInstructInfo(sample_id, ins_id, thread_id);
}

/**
 * Push a position in last position list (max: 5)
 */
function positionPushLast(pos){
	for(var i=4; i>=1; i--){
		undo[i]=undo[i-1];
	}
	undo[0] = pos;
}

/**
 * Pop the last position
 */
function positionPopLast(){
	var r = undo[0];
	for(var i=0; i<4; i++){
		undo[i]=undo[i+1];	
	}
	undo[4]=-1;
	return r;
}
