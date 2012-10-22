/**
 * Copyright (C) 2012 Malwasm Developers.
 * This file is part of Malwasm - https://code.google.com/p/malwasm/
 * See the file LICENSE for copying permission.
 * utils.js 
 *                  _                             
 *  _ __ ___   __ _| |_      ____ _ ___ _ __ ___  
 * | '_ ` _ \ / _` | \ \ /\ / / _` / __| '_ ` _ \ 
 * | | | | | | (_| | |\ V  V / (_| \__ \ | | | | |
 * |_| |_| |_|\__,_|_| \_/\_/ \__,_|___/_| |_| |_|
 *
 * Descriptions:
 * utils functions needs by the application.
 */

/**
 * Add format string function to the String class
 *
 * Returns:
 * (string) a formated string
 */
String.prototype.format = String.prototype.f = function(){
	var s = this, i = arguments.length;

	while (i--){
		s = s.replace(new RegExp('\\{' + i + '\\}', 'gm'), 
			arguments[i]);
	}
	return s;
};

/**
 * Compute the eflags for a position
 *
 * Parameters:
 * (int) eflags - eflags register value
 * (int) pos - pos of the flag we want to read
 *
 * Returns:
 * (bool) status of the flag at pos value
 */
function getFlag(eflags, pos){
	return ((eflags & (1 << pos)) != 0);
}

/**
 * Unpack a int in char format with a len of 4
 * if is a non ascii value we show a dot
 * 
 * Parameters:
 * (int) n - the number to unpack
 * 
 * Returns:
 * (string) string of length 4
 */
function intToChars(n,type){
	var r = "";
	if (type==undefined) {
		type=4;
	}
	for(var i=0; i < type; ++i){
		var c = ((n>>(8*i)) & 0xff);
		if (32 <= c && c <= 126 && c!= 32){
			r += $('<div />').text(String.fromCharCode(c)).html();
		}else if (c == 32){
			r += "&nbsp;";
		}else{
			r += '.';
		}
	}
	return r;
}

/**
 * Extract keys of an object
 *
 * Parameters:
 * (object) obj
 * 
 * Returns:
 * (Array) array with all key of the object
 */
function keys(obj){
	var keys = [];
	for(var key in obj){
		if(obj.hasOwnProperty(key)){
			keys.push(key);
		}
	}
	return keys;
}


/**
 * Get first element of an object
 *
 * Parameters:
 * (object) obj
 * 
 * Returns:
 * (object) first element of the object
 */
function first(obj){
	for(var key in obj){
		return obj[key];
	}
}

/**
 * Format a int i in hex with a left padding of zero
 * of len l
 *
 * Parameters:
 * (int) i - number to format in hex
 * (int) l - length of the left padding
 *
 * Returns:
 * (String) A reprenstation in hex of the number 
 *		  with a left padding
 */
function formatHex(i, l) {
	var o = i.toString(16);
	var s = '0';
	while (o.length < l) {
		o = s + o;
	}
	return o;
}

/**
 * Change value and set red color on change for div, span, ...
 */
function changeValue(box, newVal){
			var curVal = box.text();
        if(box.text() != newVal){
                box.css("color", "red");
        }else{
                box.css("color", "black");
        }
        box.text(newVal)
}
/**
 * Set in place the keyboard shortcuts
 */
function setKeyboardShortCut(){
    $("#malwasm_body").keydown(function(e) {
        // F7 key
        if(e.keyCode == 118){
            $('#stepin').click();
        }
        // F9 key
        if(e.keyCode == 120){
            $('#start').click();
        }
        // F12 key
        if(e.keyCode == 123){
            $('#pause').click();
        }
        e.stopImmediatePropagation();
    });
}
