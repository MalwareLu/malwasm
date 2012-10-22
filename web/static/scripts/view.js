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
 * Malware VIEW
 */

function View()
{
    this.initialize();
}
View.prototype = {
    initialize : function()
    {
		window.view = this;
        new Dump();
        new Stack(); 
	    // Interface Variables
        this.position_selected = $("#position_selected");
        this.position_max = $("#position_max");
        this.slider = $("#slider");
        
        // Container
        this.instruct_container = $("#instruct_container");

		// Set up event
        $("#open").click( function(e)
        {
            malwasm.loadSamplesList();
            $( "#dialog-samples" ).dialog("open");
        });
        $("#start").click( function(e)
        {
            malwasm.start();
        });
        $("#pause").click( function(e)
        {
            malwasm.stop();
        });
        $("#stepin").click( function(e)
        {
            malwasm.stepin();
        });
        $("#undo").click( function(e)
        {
            malwasm.undo();
        });
        $('#select_thread').change( function(e)
        {
            malwasm.loadThread(parseInt(e.currentTarget.value));
        });
        

        $(".address").contextMenu({
            menu: 'menu'
            },
            function(action, el, pos) {
                if( action == "follow" && dump.run==false ){
                    dump.run=true;
                    dump.follow(parseInt("0x"+$(el).text()));
                }
            }
        );

        this.position_selected.change( function (e)
        {
            if( !view.slider.isMoving )
                malwasm.goTo( view.position_selected.val() );
        });
        $('#follow_in_dump').submit( function (e)
            {
                if( dump.run==false ){
                    dump.run=true;
                    dump.follow(parseInt($('#follow_in_dump_box').val(),16));
                }
            }
        );
		// Set up interface
        // Fix the instruct_container width on every resize event
        $(window).resize( function()
            {
                var h = $(window).height() -
                        $('.toolbar').outerHeight(true) -
                        $('.toolbar_details').outerHeight(true)- 
                        $('#mainSplitter').outerHeight(true)+
                        $('#mainSplitter').height();
                $('#mainSplitter').height(h);
                $('#debug_inspector').height(h);
                $('#leftSplitter').height(h);
            }
        );
        // Trigger the resize event
        $(window).resize();
        //$('#leftSplitter').jqxSplitter({ 
        //   orientation: 'horizontal',
        //   panels: [ { size: 0.75*$('#mainSplitter')[0].offsetHeight, collapsible: false },
        //             { size: 0.25*$('#mainSplitter')[0].offsetHeight } ]
        //});
        $("#mainSplitter").kendoSplitter({
            panes: [
                { collapsible: false },
                { collapsible: false, resizable: false, size: "250px" }
            ]
        });
        $("#mainSplitter").data("kendoSplitter").bind("resize", function(e)
            {
                var h = $('#debug_inspector').outerHeight(true) -
                    $('#debug_inspector_group').outerHeight(true) -
                    $('#stack_container div').outerHeight(true);
                $('#stack_list').height(h);
                if(malwasm.ins_id!=-1 && malwasm.thread_id!=-1 && malwasm.sample_id!=-1)
                    stack.update();
            }
        );
        $("#leftSplitter").kendoSplitter({
            orientation: "vertical",
            panes: [
                { collapsible: false },
                { collapsible: true, size: "25%" }
            ]
        });
        $("#leftSplitter").data("kendoSplitter").bind("resize", function(e)
            {
                var h = $('#dump_container').outerHeight(true) -
                        $("#dump_header").outerHeight(true);
                        $('#dump_list').height(h);
                if(malwasm.ins_id!=-1 && malwasm.thread_id!=-1 && malwasm.sample_id!=-1)
                    dump.update();
            }
        );
        $(window).resize();
        this.initSamplesDialog();
        setKeyboardShortCut();
	    return;
	},
	
    /**
	 * display number of thread
	 */
	setNThread : function(data)
	{
		$('#select_thread option').remove();
		for(r in data){
			$('#select_thread').append('<option value="'+data[r]+'">' + data[r] + '</option>');
		}
	},
    // Set information about sample (id, hash, ...)
    setInfoSample : function(id, hash, filename, date, pinopt)
    {
        $("#sample_id").text(id);
        $("#sample_hash").html(hash);
        $("#sample_filename").text(filename);
        $("#sample_date").text(date);
    },
	initThread : function()
	{
		// Show instruction list
        $("#instruct_list li").remove();
		malwasm.n_ins = 0;
		for (var filename in malwasm.data['instruction']['tree']) {
            $("#instruct_list").append('<li class="instruct_filename" style="display: block;">'+
                '<div class="name">' + filename + '</div>'+
                '</li>');
            for( var section in malwasm.data['instruction']['tree'][filename]){
                $("#instruct_list").append('<li class="instruct_section" style="display: block;">'+
                '<div class="name">' + section + '</div>'+
                '</li>');
                for( var j in malwasm.data['instruction']['tree'][filename][section]){
                    var adr = malwasm.data['instruction']['tree'][filename][section][j];
                    var offset = adr - malwasm.data['instruction']['tree'][filename][section][0];
                    var style = "";
                    var row = null;                    
                    for(var i in malwasm.data['instruction']['list'][adr])
                    {
                        var row = malwasm.data['instruction']['list'][adr][i];
                        break;
                    };
                    var comment = (row.comment)?row.comment:'';
                    $("#instruct_list").append('<li id="instruction_' + adr + '" class="instruct" style="display: block;">'+
                        '<div class="name">0x' + formatHex(parseInt(offset), 8) + '</div>'+
                        '<div class="eip">0x' + formatHex(adr, 8) + '</div>'+
                        '<div class="instruction">' + row.asm + '</div>'+
                        '<div class="comment">' + comment  + '</div>'+
                        '</li>');
                    malwasm.n_ins += keys(malwasm.data['instruction']['list'][adr]).length;
                }
            }
		}

        // Set event monitor on instruction item
		$(".instruct").click(function() {
            malwasm.stop();
            if(malwasm._isRunning()) return;
            malwasm._setRunning();
			var eip = $(this).attr('id').split("_")[1];
			$(".instruct").removeClass('selected');
			$(this).addClass('selected');
            var next_ins_id = -1;
            var next_gap = -1;
            for (var k in malwasm.data['instruction']['list'][eip]){
                if(malwasm.data['instruction']['list'][eip].hasOwnProperty(k)) {
                    var cur = parseInt(k);
                    var cur_gap = Math.abs(malwasm.ins_id-cur);
                    if( cur_gap < next_gap || next_gap == -1 )
                    {
                        var next_ins_id=cur;
                        var next_gap = Math.abs(next_ins_id-malwasm.ins_id);
                    }
                }
            }
			malwasm.goTo(next_ins_id);	
		});
        
        // Prepare slider
		this.position_max.text(malwasm.n_ins-1);
		this.position_selected.attr("min",0);
		this.position_selected.attr("max",malwasm.n_ins-1);
		this.position_selected.css("width",10+10*malwasm.n_ins.toString().length);
		this.slider.slider({
            value: 0,
            min: 0,
            max: malwasm.n_ins,
	        step: 1,
            slide: function(event, ui)
                {
                    if( !view.slider.isMoving ) view.slider.isMoving = true;
                    view.position_selected.val( view.slider.slider('value') );
                },
        	change:  function(event, ui)
                {
                    if( malwasm.ins_id != view.slider.slider('value') )
						malwasm.goTo( view.slider.slider('value') );
                    view.slider.isMoving = false;
				}
        });
        this.slider.isMoving=false;
		
        dump.update_memRange();
	},

	/**
	 * Init the samples selection dialog
	 */
	initSamplesDialog : function(){
		$( "#dialog-samples" ).dialog({
			autoOpen: true,
			height: 400,
			width: 800,
			modal: true,
			open: window.malwasm.loadSamplesList
		});
	},
	
    /**
	 * Display the samples list with a ajax call
	 */
	displaySamplesList : function( data ){
		$("#samples tbody tr").remove();
		for(var r in data){
			var s = data[r];
			var t = "<tr id='sample_"+s.id+"'>" +
				"<td><a onclick='malwasm.openSample("+s.id+")'><img src='static/images/download.png'</a></td>" +
				"<td>" + s.id + "</td>" +
				"<td>" + s.md5 + "</td>" +
				"<td>" + s.filename + "</td>" +
				"<td>" + s.pin_param + "</td>" +
				"<td>" + s.insert_at+ "</td>" +
				"</tr>";
			$("#samples tbody").append(t);
		}
	},
	
    /**
	 * Close the samples list box
	 */
	closeSamplesList : function ()
	{
		$( "#dialog-samples" ).dialog("close");
	},
	keys : function(obj)
	{
		var keys = [];
		for(var key in obj){
			if(obj.hasOwnProperty(key)){
				keys.push(key);
			}
		}
		return keys;
	},

    /**
     * Update information in web interface
     */
    update : function(){
        // Position
        this.position_selected.val( malwasm.ins_id );
        this.slider.slider( "value", malwasm.ins_id );
        this.slider.slider('option', 'change').call(slider);
        
        // Selected class on instruction list and scroll to the current instruction
        var cur_ins = $("#instruction_"+malwasm.data['register']['eip']);
        $('.selected').removeClass("selected");
        cur_ins.addClass("selected");
        var c_pos = $('#instruct_container').scrollTop();
        var pos = cur_ins.offset().top - $('#instruct_container').offset().top;
        var h = $('#instruct_container').height() - 8;
        if (pos > h || pos < 0) {
            $('#instruct_container').scrollTop(pos + c_pos);
        }
        
        // Register
        for(var r in register_var ){
            changeValue($("#debug_inspector_"+register_var[r]),formatHex( malwasm.data['register'][register_var[r]],8));
        }

        /*
         * eflags we want to display:
         *  11 10  9  8  7  6  5  4  3  2  1  0
         *  OF DF    TF SF ZF    AF    PF    CF 
         */
        for (r in eflags_var){
            var val = getFlag( malwasm.data['register']['eflags'], eflags_var[r].pos)
            changeValue($("#debug_inspector_"+r+"flag"),+val);
        }
        
        // References
        var adr = malwasm.data['register']['eip'];
        // Get refs for the current adr
        var refs = malwasm.data['instruction']['list'][adr];
        var refsKey = [];
        for (var u in refs) refsKey.push(u);
        refsKey.sort(function(a,b){return parseInt(a)-parseInt(b)});
        // Remove all old references
        $('#inspector_ref li').remove();

        // Construct the news references
        for (var x=0; x<refsKey.length; x++ ){
            var r = refsKey[x];
            var style = '';
            if (r == malwasm.ins_id){
                var style = ' selected';
            }
            var t = '<li id="refs_'+r+'" class="ins_ref'+style+'">'+r+'</li>';
            $('#inspector_ref').append(t);
        }
        var c_pos = $('#inspector_ref').scrollTop();
        var pos = $("#inspector_ref li.selected").offset().top - $('#inspector_ref').offset().top;
        var h = $('#inspector_ref').height();
        if (pos > h || pos < 0){
            $('#inspector_ref').scrollTop(pos + c_pos);
        }
        $(".ins_ref").click(function() {
            var id = $(this).attr('id').split("_")[1];
            $(".ins_ref").removeClass('selected');
            $(this).addClass('selected');
            malwasm.goTo(id);
        });

        // Stack
        stack.update();
        // Dump
        dump.update();
    },
    updateSelectedInstruction : function()
	{
        var cur_ins = $("#instruction_"+malwasm.data['register']['eip']);
		// select the row in the div #instruct_list
		$('.selected').removeClass("selected");
		cur_ins.addClass("selected");
		var c_pos = $('#instruct_container').scrollTop();
		var pos = cur_ins.offset().top - $('#instruct_container').offset().top;
		var h = $('#instruct_container').height() - 8;
		//console.log(c_pos + " " + pos + " " + h);
		if (pos > h || pos < 0) {
			$('#instruct_container').scrollTop(pos + c_pos);
		}
	},
	getDumpType : function()
	{
		return $("#dump_select").val();
	}
}
