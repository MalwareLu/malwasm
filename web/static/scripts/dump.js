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
 * Dump manager
 */

function Dump()
{
    this.initialize();
}
Dump.prototype = {
    initialize : function()
    {
        window.dump = this;
        this.type = -1;
        this.nb_line_show_first = 20;
        this.run = false;
        this.cur_adr = -1;
        this.rid = -1;
        this.adr_top = -1;
        this.adr_bot = -1;
        this.dump_list = $('#dump_list')[0];
        this.line_size = -1;
        this.line_focus = -1;
        this.resize_height=-1;
        // Interface Variables
        // Container
        this.dump_container = $("#dump_container")[0];
        $("#dump_select").change( function()
        {
            if(dump.run) return;
            dump.update();
        });
        $("#dump_group").change( function()
        {
            if(dump.run) return;
            dump.update();
        });
        $("#dump_nb_group_line").change( function()
        {
            if(dump.run) return;
            dump.update();
        });
        $('#dump_list').scroll( function(eObj)
        {
            if(dump.run){
                dump._save_current_line();
                return;
            }
            if(eObj.currentTarget.scrollTop > eObj.currentTarget.scrollHeight-eObj.currentTarget.offsetHeight-10 )
            {
                dump.down();
            }else if (eObj.currentTarget.scrollTop < 10)
            {
                dump.up();
            }
            return;
        });
        $('#dump_all a').click( function(eventObject)
        {
            if(dump.run) return;
            dump.all();
            $('#dump_all').css('display','none');
        });
        return;
    },
    update : function()
    {
        try{
            this.run=true;
            var rid = $("#dump_select").val();
            this.grp = parseInt($("#dump_group").val());
            this.grp_line = parseInt($("#dump_nb_group_line").val());
            this.nb_line_show_first = Math.round(this.dump_container.offsetHeight/12);
            this.nb_line_show_first +=3;
            this.line_size = this.grp*this.grp_line*this.nb_line_show_first;
            this.info = -1;
            $('#dump_all').css('display','inline');
            
            if(malwasm.ins_id < malwasm.data['memRange'][rid]['min_ins_id'])
            {
                this.rid=-1;
                this.run = false;
                $('#dump_list li').remove();
                return;
            }
            // Save address
            if (rid == this.rid){
                this._save_current_line(); 
            }else{
                this.rid = rid;
                this.cur_adr = -1;
            }
            if(malwasm.ins_id < malwasm.data['memRange'][this.rid]['min_ins_id'])
            {
                this.run = false;
                alert("Sorry :'( It's not yet available");
                return;
            }
            for( var i in malwasm.data['memRange'][this.rid]['list'] )
            {
                if( malwasm.data['memRange'][this.rid]['list'][i]['ins_id'] <= malwasm.ins_id)
                {
                    if( this.info == -1 )
                    {
                        this.info = malwasm.data['memRange'][this.rid]['list'][i];
                    }else{
                        if (malwasm.data['memRange'][this.rid]['list'][i]['ins_id'] > this.info['ins_id'])
                            this.info = malwasm.data['memRange'][this.rid]['list'][i];
                    }
                }
            }
            if( this.info == -1)
            {
                this.run = false;
                return;
            }
            var url = "dump?sample_id=" + malwasm.sample_id + "&ins_id=" + malwasm.ins_id + "&thread_id=" + malwasm.thread_id
                        + "&start=" + this.info.adr_start + "&stop=" + this.info.adr_stop;
            $('#dump_download').attr('href', url);
            if( this.line_focus == -1 ) this.line_focus = this.info.adr_start;
            if(this.cur_adr  == -1){
                this.cur_adr = this.info.adr_start;
            }else{
                this.cur_adr = this.line_focus;
            }
            this.adr_top = this.cur_adr;

            // Remove all old element of the div #stack_list
            $('#dump_list li').remove();

            if (this.adr_top+this.line_size > this.info.adr_stop)
            {
                this.adr_bot = this.info.adr_stop;
            }else{
                this.adr_bot = this.adr_top + this.line_size;
            }
            models.loadMemByRange( this.adr_top, this.adr_bot, function(e)
                {
                    try{
                        dump.show( e.currentTarget.response, 1 );
                    }finally{
                        dump.run=false;
                    }
                }
            );
        }catch(e){
            this.run = false;
            $('#dump_list li').remove();
        }
    },
    show : function( data, way )
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
        if( way == 1 ){
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
                // Concat ASCII equivalent
                var comment = "";
                for(var j=0; j<this.grp_line; j++){
                    if( j!=0 ) comment +=" ";
                    if (val[j] != -1)
                        comment += intToChars(val[j],this.grp);
                }
                var valHex = "";
                for(var j=0;j<this.grp_line;j++) {
                    if(j!=0) valHex += "&nbsp;";
                    if (val[j] != -1){
                        valHex += "<div style=\"display: inline-block;\" ";
                        if (this.grp==4) valHex +="class=\"address\"";
                        valHex += ">"+formatHex(val[j], this.grp*2)+"</div>";
                    }else{
                        valHex += "&nbsp;";
                        for(var z=0; z<this.grp; z++) valHex += "&nbsp;&nbsp;";
                    }
                }
                var t = '<li id="dump_' + formatHex(this.cur_adr, 8) + '" class="dump">' +
                        '<div class="adr">' + formatHex(this.cur_adr, 8) + '</div>' +
                        '<div class="value">' + valHex + '</div>' +
                        '<div class="comment">' + comment + '</div>' +
                        '</li>';
                $('#dump_list').append(t);
                if(this.grp==4){
                    $("#dump_" + formatHex(this.cur_adr, 8)+" .address").contextMenu({
                        menu: 'menu'
                        },
                        function(action, el, pos) {
                            if( action == "follow" && dump.run==false ){
                                dump.run=true;
                                dump.follow(parseInt("0x"+$(el).text()));
                            }
                        }
                    );
                }
                this.cur_adr += this.grp*this.grp_line;
            }
        }else if ( way == 0 ){
            for (var i=dmpGrp.length-1; i>=0; i-=this.grp_line){
                var val = new Array();
                // Get the current value
                for (var j=0; j<this.grp_line; j++) val[this.grp_line-j-1]= dmpGrp[i-j];
                // Concat ASCII equivalent
                var comment = "";
                for(var j=0; j<this.grp_line; j++){
                    if( j!=0 ) comment +=" ";
                    if (val[j] != -1)
                        comment += intToChars(val[j],this.grp);
                }
                var valHex = "";
                for(var j=0;j<this.grp_line;j++) {
                    if(j!=0) valHex += "&nbsp;";
                    if (data[j] != -1){
                        valHex += "<div style=\"display: inline-block;\" ";
                        if (this.grp==4) valHex +="class=\"address\"";
                        valHex += ">"+formatHex(val[j], this.grp*2)+"</div>";
                    }else{
                        valHex += "&nbsp;";
                        for(var z=0; z<this.grp; z++) valHex += "&nbsp;&nbsp;";
                    }
                }
                var t = '<li id="dump_' + formatHex(this.cur_adr, 8) + '" class="dump">' +
                        '<div class="adr">' + formatHex(this.cur_adr, 8) + '</div>' +
                        '<div class="value">' + valHex + '</div>' +
                        '<div class="comment">' + comment + '</div>' +
                        '</li>';
                $('#dump_list').prepend(t);
                if(this.grp==4){
                    $("#dump_" + formatHex(this.cur_adr, 8)+" .address").contextMenu({
                        menu: 'menu'
                        },
                        function(action, el, pos) {
                            if( action == "follow" && dump.run==false ){
                                dump.run=true;
                                dump.follow(parseInt("0x"+$(el).text()));
                            }
                        }
                    );
                }
                this.cur_adr -= this.grp*this.grp_line;
            }
        }
        if(this.line_focus != -1){ 
            if($("#dump_"+formatHex(this.line_focus, 8)).length > 0){
                this.dump_list.scrollTop = $("#dump_"+formatHex(this.line_focus, 8))[0].offsetTop - this.dump_list.offsetTop;
                this.line_focus = -1;
            }
        }
        return true;
    },
    up : function()
    {
        this.run=true;
        try{
            this._save_current_line();
            if (this.adr_top <= this.info.adr_start){
                this.run=false;
                return;
            }
            this.cur_adr = this.adr_top;
            if (this.adr_top - this.line_size < this.info.adr_start)
            {
                this.adr_top = this.info.adr_start;
            }else{
                this.adr_top = this.adr_top-this.line_size;
            }
            models.loadMemByRange( this.adr_top, this.cur_adr, function(e)
                {
                    try{
                        dump.show( e.currentTarget.response, 0 );
                    }finally{
                        dump.run=false;
                    }
                }
            );
        }catch(e){
            dump.run=false;
        }
    },
    down : function()
    {
        this.run=true;
        try{
            if (this.adr_bot >= this.info.adr_stop){
                this.run=false;
                return;
            }
            this.cur_adr=this.adr_bot;
            if (this.adr_bot+this.line_size > this.info.adr_stop)
            {
                this.adr_bot = this.info.adr_stop;
            }else{
                this.adr_bot = this.adr_bot+ this.line_size;
            }
            models.loadMemByRange( this.cur_adr, this.adr_bot, function(e)
                {
                    try{
                        dump.show( e.currentTarget.response, 1);
                    }finally{
                        dump.run=false; 
                    }
                }
            );
        }catch(e){
            this.dump=false;
        }
    },
    all : function()
    {
        try{
            if(this.adr_bot >= this.info.adr_stop) return false;
            dump.run=true;
            this.cur_adr=this.adr_bot;
            this.adr_bot=this.info.adr_stop;
            models.loadMemByRange( this.cur_adr, this.info.adr_stop, function(e)
                {
                    try{
                        dump.show( e.currentTarget.response, 1);
                        if( dump.adr_top <= dump.info.adr_start ){
                            dump.run=false;
                        }else{
                            dump._save_current_line();
                            dump.cur_adr=dump.adr_top;
                            dump.adr_top=dump.info.adr_start;
                            models.loadMemByRange( dump.adr_top, dump.cur_adr, function(e)
                            {
                                    try{
                                        dump.show( e.currentTarget.response, 0);
                                    }finally{
                                        dump.run=false;
                                    }
                                }
                            );
                        }
                    }catch(e){
                        dump.run=false;
                    }
                }
            );
        }finally{
            dump.run=false;
            return true;
        }
    },
    update_memRange : function()
    {
        $('#dump_select option').remove();
        for(var i in malwasm.data['memRange'])
        {
            var t = '<option value="'+i+'">'
                  + formatHex( malwasm.data['memRange'][i]['adr_start'],8).toUpperCase() + ' - '
                  + formatHex( malwasm.data['memRange'][i]['adr_stop'],8).toUpperCase()
                  + '</option>';
           $('#dump_select').append(t); 
        }
    },
    /**
     * Highlight an address in the dump when it's possible
     *
     * Paramater:
     * (int) adr: address to highligh
     */
    follow : function ( adr ){
        try{
            this.run=true;
            this.grp = parseInt($("#dump_group").val());
            this.grp_line = parseInt($("#dump_nb_group_line").val());
            this.nb_line_show_first = Math.round(this.dump_container.offsetHeight/12);
            if(this.nb_line_show_first < 3) this.nb_line_show_first+=3;
            this.line_size = this.grp*this.grp_line*this.nb_line_show_first;
            this.info = -1;
            $('#dump_all').css('display','inline');
            this.cur_adr=-1;
            // Find the memory range which contains the target address
            for(var i in malwasm.data['memRange']){
                if( adr >= malwasm.data['memRange'][i].adr_start && adr <= malwasm.data['memRange'][i].adr_stop ){
                    if(malwasm.ins_id < malwasm.data['memRange'][i]['min_ins_id'])
                    {
                        this.run = false;
                        return;
                    }
                    for( var k in malwasm.data['memRange'][i]['list'] )
                    {
                        if( malwasm.data['memRange'][i]['list'][k]['ins_id'] <= malwasm.ins_id)
                        {
                            if( this.info == -1 )
                            {
                                this.info = malwasm.data['memRange'][i]['list'][k];
                            }else{
                                if (malwasm.data['memRange'][i]['list'][k]['ins_id'] > this.info['ins_id'])
                                this.info = malwasm.data['memRange'][i]['list'][k];
                            }
                        }
                    }
                    if( this.info == -1)
                    {
                        this.run = false;
                        return;
                    }
                    this.cur_adr=adr;
                    this.rid=i;
                    $("#dump_select").val(i);
                    var url = "dump?sample_id=" + malwasm.sample_id +
                              "&ins_id=" + malwasm.ins_id +
                              "&thread_id=" + malwasm.thread_id +
                              "&start=" + this.info.adr_start +
                              "&stop=" + this.info.adr_stop;
                    $('#dump_download').attr('href', url);
                    this.line_focus= -1;
                    var line = this.grp*this.grp_line;
                    for(var j = this.info.adr_start; j<this.info.adr_stop; j+= line){
                        if( this.cur_adr >= j && this.cur_adr < j+line){
                            this.line_focus = j;
                            break;
                        }
                    }
                    if (this.line_focus == -1 )
                        this.line_focus=this.info.adr_start;
                    this.adr_top = this.line_focus;
                    this.cur_adr=this.adr_top;
                    // Remove all old element of the div #stack_list
                    $('#dump_list li').remove();
        
                    if (this.adr_top+this.line_size > this.info.adr_stop)
                    {
                        this.adr_bot = this.info.adr_stop;
                    }else{
                        this.adr_bot = this.adr_top + this.line_size;
                    }
                    models.loadMemByRange( this.adr_top, this.adr_bot, function(e)
                    {
                        try{
                            dump.show( e.currentTarget.response, 1 );
                        }finally{
                            dump.run=false;
                        }
                    })
                    this.run=false;
                    return;
                }
            }
        }finally{
            this.run=false;
        }
    },
    _save_current_line : function(){
        var offset_adr_display = this.dump_list.scrollTop + this.dump_list.offsetTop;
        var li_scrollTop = -1;
        for(var row in this.dump_list.children)
        {
            if ( Math.abs( this.dump_list.children[row].offsetTop - offset_adr_display ) <= 15 )
            {
                if( li_scrollTop == -1 )
                {
                    var li_scrollTop = dump_list.children[row];
                }else if ( Math.abs(this.dump_list.children[row].offsetTop - offset_adr_display )
                             < Math.abs(li_scrollTop.offsetTop - offset_adr_display))
                {
                    var li_scrollTop = this.dump_list.children[row];
                }
            }
        }
        if ( li_scrollTop != -1){
                for( var row in li_scrollTop.attributes )
                {
                    if( li_scrollTop.attributes[row].isId )
                        var hexAdr_scrollTop = li_scrollTop.attributes[row].value.replace(new RegExp('dump_', 'g'),'');
                }
                this.line_focus = parseInt( "0x" + hexAdr_scrollTop );
            }else{
                this.line_focus = -1;
        } 
    }
}
