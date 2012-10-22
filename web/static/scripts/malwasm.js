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
 * Malwasm web interface class
 */

function Malwasm()
{
	this.initialize();
}
Malwasm.prototype = {
	initialize : function()
	{
		// Init variable
		window.malwasm = this;
		this.sample_id = -1;
		this.thread_id = -1;
		this.ins_id = -1;
		this.n_ins = -1;
		this._undo = [];

        //Init global variable
        register_var = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp','esp','eip','eflags'];
        eflags_var = {
            'c': { 'pos':0 },
            'p': { 'pos':2 },
            'a': { 'pos':4 },
            'z': { 'pos':6 },
            's': { 'pos':7 },
            't': { 'pos':8 },
            'd': { 'pos':10 },
            'o': { 'pos':11 },
        };

        // Data structure
        this.data = {};
        this.data['instruction']={};
        this.data['instruction']['tree']={};
        this.data['instruction']['list']={};
        this.data['register']={};
        this.data['memRange']=[];

        this.run_interval=-1;
        this.interval=-1;
		for(var i=0;i<undoSize;i++) this._undo[i]=-1;
		this.run = false;
        this.next_ins_id = -1;
		new Models();		
		new View();
	},
	
	//
	//
	//
	// Event management
	//
	//
	/*
	 * Open sample
	 */
	openSample : function(id)
	{
        this.loadSample(id);
		view.closeSamplesList();
	},
    _play : function(){
        if(!this.play) return;
        if (malwasm.ins_id >= malwasm.n_ins-1){
            this.stop();
            return;
        }else if(!this._isRunning()){
            malwasm.goTo(++malwasm.ins_id);
        }
        setTimeout(function(){malwasm._play()}, 1000);
    },
	/*
	 * Play the instruction untill the end
	 */ 
	start : function()
	{
        if(this._isRunning() || this.play) return;
        this.play=true;
        this._play();
	},

    /**
     * Pause
     */
    stop : function()
    {
        this.play=false;
    },
	/**
	 * Move by one
	 */
	stepin : function()
	{
		this.stop();
        if (malwasm.ins_id >= malwasm.n_ins-1)return;
        if(this._isRunning()) return;
        this._setRunning();
		this.goTo(++this.ins_id);
	},

	//
	//
	// Action management
	//
	//

	/**
	 * Go to the instruction ID in argument
	 *
	 * Parameters:
	 * (int) ins_id: instruction ID to move
 	 */
	goTo : function(ins_id)
	{
        this._undoListPush(this.ins_id);
        this.setInstructionId(ins_id);
	},
	
    /**
	 * Set the instruction ID
	 *
	 * Parameters:
 	 * (int) ins_id: the new instruction ID
	 */
	setInstructionId : function(ins_id)
	{
        // Check if ins_id is correct.
        // In case of incorrect argument, ins_id take the value 0
        if(ins_id >=0 && ins_id < this.n_ins){
            this.ins_id = ins_id;
        }else{
            this.ins_id = 0;
        }
        var url = "instruction?sample_id=" + malwasm.sample_id +
                  "&ins_id=" + malwasm.ins_id +
                  "&thread_id=" + malwasm.thread_id;
        $.ajax({
            type: "GET",
            url: url,
            dataType: "json",
            error: function( objRequest ){
                alert(objRequest.statusText);
            },
            success: function(data)
            {
                for(var r in register_var){    
                    malwasm.data['register'][register_var[r]] = data[register_var[r]];
                }
                view.update();
            }
        });
	},

    // return the state of instruction load
    _isRunning : function(){
        return dump.run || stack.run;
    },

    // Set the state of instruction load as run
    _setRunning : function(){
        dump.run=true;
        stack.run=true;
    },
	/**
	 * Cancel position change
	 */
	undo : function()
	{
		var r = this._undoListPop();
        	if( r != -1){
                	this.setInstructionId(r)
        	}else{
                	alert("I don't remember");
        	}
	},

	/**
	 * Get samples list
	 */
	loadSamplesList : function ()
	{
		models.getSamplesList()
	},

	/**
	 * Pop a value on undo list
	 */
	_undoListPop : function()
	{
		var r = this._undo[0];
        	for(var i=0; i<undoSize; i++)
		{
			this._undo[i] = this._undo[i+1];
		}
        	this._undo[undoSize] = -1;
        	return r;
	},

	/**
	 * Push a value on undo list
	 *
	 * Paramters:
	 * (int) ins_id: instruction ID to push in undo list
	 */ 
	_undoListPush : function( ins_id )
	{
		for(var i=undoSize; i>=1; i--){
                	this._undo[i] = this._undo[i-1];
        	};
        	this._undo[0] = this.ins_id;
	},

	/**
	 * load Sample information:
	 * 	- information about sample
	 * 	- number of thread 
	 */
	loadSample : function(sample_id)
	{
		this.sample_id = sample_id;
		var hash = $("#sample_" + sample_id + " td:nth-child(3)").text();
		var filename = $("#sample_" + sample_id + " td:nth-child(4)").text();
		var pinopt = $("#sample_" + sample_id + " td:nth-child(6)").text();
		var date = $("#sample_" + sample_id + " td:nth-child(6)").text();
		view.setInfoSample(sample_id, hash, filename, date, pinopt);
		models.getNbThread();
        $('#select_thread option[value="0"]').attr('selected', 'selected');
        this.loadThread(0);
	},

	/**
	 * Load Sample
	 */
	loadThread : function(thread_id)
	{
		this.thread_id = thread_id;
        // Reset undo
        for(var i=0;i<undoSize;i++) this.undo[i]=-1;
        $.ajax({
            type: "GET",
            url: "threadInfo?sample_id=" + malwasm.sample_id + "&thread_id=" + malwasm.thread_id,
            dataType: "json",
            error: function( objRequest ){
                    alert(objRequest.statusText);
                   },
            success: function(data){
                        malwasm.data['instruction']['tree'] = data['tree'];
                        malwasm.data['instruction']['list'] = data['instruction'];
                        malwasm.data['memRange'] = data['memRange'];
                        view.initThread();
                        malwasm.goTo(0);
                     }
        });
	},
}
