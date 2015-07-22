// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This function is called by common.js when the NaCl module is
// loaded.
function moduleDidLoad() {
  // Once we load, hide the plugin. In this example, we don't display anything
  // in the plugin, so it is fine to hide it.
  common.hideModule();
  // After the NaCl module has loaded, common.naclModule is a reference to the
  // NaCl module's <embed> element. 
//  common.naclModule.postMessage('Kunal Baweja'); 
}

// This function is called by common.js when a message is received from the
// NaCl module.
function handleMessage(message) {
	var view = new Uint8Array(message.data);
	console.log(view);
  var str = String.fromCharCode.apply(null,new Uint8Array(message.data));
  console.log(str);

  var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
  var bufView = new Uint8Array(buf);
  var len = str.length;
  for(var i=0; i<len; i++)
  {
  	bufView[i] = str.charCodeAt(i);
  }
  console.log(bufView);
}
