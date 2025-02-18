(function () {
    'use strict';
    
    var imagePath = '';
  
    // RPC Exports for setting the image path
    rpc.exports = {
      init(stage, parameters) {
        imagePath = parameters.image;
        console.log("[+] Image path set to:", imagePath);
        return true;
      },
      dispose() {
        console.log("[dispose]");
      }
    };
  
    function debugLog(message) {
      console.log(`[DEBUG] ${message}`);
    }
  
    if (Java.available) {
      Java.perform(function () {
        debugLog("Starting aggressive image injection script");
  
        // Import necessary Java classes
        var FileInputStream = Java.use('java.io.FileInputStream');
        var File = Java.use('java.io.File');
        var BitmapFactory = Java.use('android.graphics.BitmapFactory');
        var CompressFormat = Java.use('android.graphics.Bitmap$CompressFormat');
  
        // Advanced byte reading function
        function readBytesFromFile(filePath) {
          try {
            var file = File.$new(filePath);
            if (!file.exists()) {
              debugLog(`File does not exist: ${filePath}`);
              return null;
            }
  
            var fis = FileInputStream.$new(file);
            var length = file.length().toNumber();
            debugLog(`File length: ${length} bytes`);
  
            var buffer = Java.array('byte', new Array(length));
            var bytesRead = fis.read(buffer);
            
            fis.close();
            
            debugLog(`Successfully read ${bytesRead} bytes`);
            return buffer;
          } catch (error) {
            debugLog(`Error reading file: ${error}`);
            return null;
          }
        }
  
        // Multiple aggressive hooking strategies
        function installAggressiveHooks() {
          debugLog("Installing aggressive image injection hooks");
  
          // Hook multiple Activity result methods
          var Activity = Java.use('android.app.Activity');
          
          // Hook all possible onActivityResult overloads
          Activity.onActivityResult.overloads.forEach(function(method) {
            method.implementation = function() {
              debugLog(`Intercepted onActivityResult with ${arguments.length} arguments`);
              
              // Convert arguments to array for easier manipulation
              var args = Array.from(arguments);
              
              // Check for potential camera result (assuming 2nd or 3rd arg might be Intent)
              var data = args.find(arg => arg && arg.$className && arg.$className.includes('Intent'));
              var resultCode = args.find(arg => typeof arg === 'number' && arg === -1);
  
              if (data && resultCode && imagePath !== '') {
                try {
                  debugLog("Potential camera result detected");
                  
                  // Read replacement image bytes
                  var replacementBytes = readBytesFromFile(imagePath);
                  if (!replacementBytes) {
                    debugLog("Failed to read replacement image bytes");
                    return this.onActivityResult.apply(this, arguments);
                  }
  
                  // Decode replacement bitmap
                  var replacementBitmap = BitmapFactory.decodeByteArray(
                    replacementBytes, 
                    0, 
                    replacementBytes.length
                  );
  
                  if (!replacementBitmap) {
                    debugLog("Failed to decode replacement bitmap");
                    return this.onActivityResult.apply(this, arguments);
                  }
  
                  // Replace thumbnail data if available
                  if (data.hasExtra("data")) {
                    debugLog("Replacing thumbnail data");
                    data.putExtra("data", replacementBitmap);
                  }
  
                  // Replace image URI
                  var imageUri = data.getData();
                  if (imageUri) {
                    debugLog(`Image URI detected: ${imageUri}`);
                    try {
                      var contentResolver = this.getContentResolver();
                      var outputStream = contentResolver.openOutputStream(imageUri);
                      
                      if (outputStream) {
                        debugLog("Writing replacement bitmap to output stream");
                        replacementBitmap.compress(
                          CompressFormat.JPEG.value, 
                          100, 
                          outputStream
                        );
                        outputStream.flush();
                        outputStream.close();
                        debugLog("Successfully wrote replacement bitmap");
                      }
                    } catch (uriError) {
                      debugLog(`URI replacement error: ${uriError}`);
                    }
                  }
                } catch (error) {
                  debugLog(`Overall replacement error: ${error}`);
                }
              }
  
              // Call original method
              return this.onActivityResult.apply(this, arguments);
            };
          });
  
          // Additional hooks for camera-related classes
          try {
            // Hook Camera Intent creation
            var Intent = Java.use('android.content.Intent');
            Intent.setAction.implementation = function(action) {
              debugLog(`Intent action set: ${action}`);
              return this.setAction(action);
            };
  
            // Hook camera-related method calls
            var Camera = Java.use('android.hardware.Camera');
            if (Camera) {
              Camera.takePicture.implementation = function() {
                debugLog("Camera.takePicture() intercepted");
                return this.takePicture.apply(this, arguments);
              };
            }
  
            // Hook ImageReader for additional coverage
            var ImageReader = Java.use('android.media.ImageReader');
            if (ImageReader) {
              ImageReader.acquireLatestImage.implementation = function() {
                debugLog("ImageReader.acquireLatestImage() intercepted");
                return this.acquireLatestImage.apply(this, arguments);
              };
            }
          } catch (hookError) {
            debugLog(`Additional hooks error: ${hookError}`);
          }
  
          debugLog("Aggressive image injection hooks installed successfully");
        }
  
        // Install hooks
        installAggressiveHooks();
      });
    } else {
      console.log("[-] Java environment not available");
    }
  })();