Java.perform(function () {
    // Hook ImageReader's setOnImageAvailableListener method
    var ImageReader = Java.use("android.media.ImageReader");
    var customListener = Java.use("android.media.ImageReader$OnImageAvailableListener");

    Java.retain(ImageReader);
    Java.retain(customListener);

    var retainedListeners = [];

    // Hook setOnImageAvailableListener(listener, handler)
    ImageReader.setOnImageAvailableListener.overload(
        "android.media.ImageReader$OnImageAvailableListener",
        "android.os.Handler"
    ).implementation = function (listener, handler) {
        console.log("setOnImageAvailableListener called.");
        console.log("This object: ", this);
        console.log("Listener: ", listener);
        console.log("Handler: ", handler);

        if (listener) {
            // Create a custom listener
            var CustomImageAvailableListener = Java.registerClass({
                name: "com.hsbc.digl.listener",
                implements: [customListener],
                methods: {
                    onImageAvailable: function (reader) {
                        console.log("Custom listener called. Reader: ", reader);

                        try {
                            // Get the original image
                            var image = reader.acquireLatestImage();
                            if (image) {
                                console.log(`Original Image: ${image}`);

                                // Read the custom image data from a file
                                var File = Java.use("java.io.File");
                                var FileInputStream = Java.use("java.io.FileInputStream");
                                var ByteBuffer = Java.use("java.nio.ByteBuffer");
                                var BitmapFactory = Java.use("android.graphics.BitmapFactory");

                                var file = File.$new("/data/local/tmp/hsbc.jpg");
                                var fis = FileInputStream.$new(file);
                                var customImageData = ByteBuffer.allocate(fis.available());
                                fis.read(customImageData.array());
                                fis.close();

                                // Replace the original image with the custom image
                                var customImage = BitmapFactory.decodeByteArray(
                                    customImageData.array(),
                                    0,
                                    customImageData.remaining()
                                );

                                console.log("Custom image created successfully.");

                                // Close the original image
                                image.close();

                                // Return the custom image (if required)
                                return customImage;
                            }
                        } catch (e) {
                            console.log("Error processing image: ", e);
                        } finally {
                            if (image) {
                                image.close();
                            }
                        }

                        // Call the original listener method
                        listener.onImageAvailable(reader);
                    },
                },
            });

            // Retain and store the custom listener instance
            var wrappedInstance = CustomImageAvailableListener.$new();
            Java.retain(wrappedInstance);
            retainedListeners.push(wrappedInstance);

            console.log("Custom listener retained and stored!");

            // Call the original setOnImageAvailableListener with the custom listener
            return this.setOnImageAvailableListener(wrappedInstance, handler);
        } else {
            console.log("Listener not provided.");
        }

        // Default behavior
        return this.setOnImageAvailableListener(listener, handler);
    };
});
