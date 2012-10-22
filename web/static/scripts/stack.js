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
 * Stack manager
 */

function Stack()
{
    this.initialize();
}
Stack.prototype = {
    initialize : function()
    {
		window.stack = this;
        this.type = -1;
        this.nb_line_show_first = 20;
        this.run = false;
        this.cur_adr = -1;
        this.grp = 4;
        this.grp_line = 1;
        this.stack_container = $("#stack_container");
        $('#stack_list').scroll( function(eObj)
            {
                if(stack.run)return;
                if(eObj.currentTarget.scrollTop > eObj.currentTarget.scrollHeight-eObj.currentTarget.offsetHeight-10 )
                    stack.more();
            }
        );
        $('#stack_all a').click( function(eventObject)
            {
                if(stack.run) return;
                $('#stack_all').css('display','none');
                stack.all();
            });
    	return;
	},
    /**
     * Function called in order to clean and load new dump
     */
    update : function()
    {
        this.run=true;
        this.range=-1;
        this.stack_list = $('#stack_list');
        this.nb_line_show_first = Math.round(($("#debug_inspector")[0].offsetHeight-$("#debug_inspector_group")[0].offsetHeight)/10);
        $('#stack_all').css('display','inline');
        $('#stack_list li').remove();
        for( var range in malwasm.data['memRange'] ){
            if( malwasm.data['register']['esp'] >= malwasm.data['memRange'][range]['adr_start'] 
             && malwasm.data['register']['esp'] < malwasm.data['memRange'][range]['adr_stop'])
            {
                this.range=range;
                break;
            }
        }
        this.cur_adr = malwasm.data['register']['esp'];
        var url = "dump?sample_id=" + malwasm.sample_id + "&ins_id=" 
                + malwasm.ins_id + "&thread_id=" + malwasm.thread_id
                + "&start=" + malwasm.data['memRange'][this.range].adr_start
                + "&stop=" + malwasm.data['memRange'][this.range].adr_stop;
        $('#stack_dump_download').attr('href', url);
        var first_items_size = stack.grp*stack.grp_line*stack.nb_line_show_first;
        if (malwasm.data['register']['esp']+first_items_size > malwasm.data['memRange'][this.range]['adr_stop'])
        {
            var adr_stop = malwasm.data['memRange'][this.range]['adr_stop'];
        }else{
            var adr_stop = malwasm.data['register']['esp']+first_items_size;
        }
        models.loadMemByRange( malwasm.data['register']['esp'], adr_stop, function(e)
        {
            stack.show( e.currentTarget.response );
            stack.run=false;
        });
	},
    /**
     * Function called when the position has changed and load the first part
     * of data
     */
	show : function( data )
	{
        if ( data == null ) {
			return;
		}
		// Convert data in array of unsigned int
		if (this.grp == 1){
			var dmpGrp = new Uint8Array(data);
		}else if(this.grp == 2){
			var dmpGrp = new Uint16Array(data);  
		}else{
			var dmpGrp = new Uint32Array(data);
		}
		for (var i=0; i<dmpGrp.length; i+=this.grp_line){
			var val = new Array();
			// Get the current value
			val[0] = dmpGrp[i];
			if( (i+this.grp_line) >= dmpGrp.length ){
				for(var j=1; j < this.grp_line; j++){
					if( (i+j) >= dmpGrp.length ){
						val[j]=-1;
					}else{
						val[j]=dmpGrp[i+j];
					}
				}
			}else{
				for (var j=0; j<this.grp_line; j++) val[j]= dmpGrp[i+j];
			}
            
            //ASCII equivalent
            var comment = "";
            if( val[0] in malwasm.data['instruction']['list'] ){
                for( var ref in malwasm.data['instruction']['list'][val[0]]){
                    comment += malwasm.data['instruction']['list'][val[0]][ref]['name'];
                    break;
                }
            }else{
                comment += intToChars(val[0],this.grp);
            }
            var valHex = formatHex(val[0], this.grp*2);

            var t = '<li id="stack_' + formatHex(this.cur_adr, 8) + '" class="stack">' +
                    '<div class="adr">' + formatHex(this.cur_adr, 8) + '</div>' +
                    '<div class="value address">' + valHex + '</div>' +
                    '<div class="comment">' + comment + '</div>' +
                    '</li>';
            this.stack_list.append(t);
            $("#stack_" + formatHex(this.cur_adr, 8)+" .address").contextMenu({
                menu: 'menu'
                },
                function(action, el, pos) {
                    if( action == "follow" && dump.run==false ){
                        dump.run=true;
                        dump.follow(parseInt("0x"+$(el).text()));
                    }
                }
            );
            this.cur_adr += this.grp*this.grp_line;
		}
		return true;
	},

    /**
     * Function called when user scroll down and load/display the next part
     * of dump
     */
    more : function()
    {
        stack.run=true;
        if (this.cur_adr > malwasm.data['memRange'][this.range]['adr_stop']) return false;
        var first_items_size = this.grp*this.grp_line*this.nb_line_show_first;
        if (this.cur_adr+first_items_size > malwasm.data['memRange'][this.range]['adr_stop'])
        {
            var adr_stop = malwasm.data['memRange'][this.range]['adr_stop'];
        }else{
            var adr_stop = this.cur_adr+first_items_size;
        }
        models.loadMemByRange( this.cur_adr, adr_stop, function(e)
            {
                stack.show( e.currentTarget.response );
                stack.run=false; 
            }
        );
    },

    /**
     * Load and display the rest of dump in stack area
     */
    all : function()
    {
        this.run=true;
        if(this.cur_adr > malwasm.data['memRange'][this.range]['adr_stop']){
            this.run=false;
            return false;
        }
        models.loadMemByRange( this.cur_adr, malwasm.data['memRange'][this.range]['adr_stop'], function(e)
            {
                stack.show( e.currentTarget.response );
                stack.run=false;
            }
        );
        return true;
    }
}
