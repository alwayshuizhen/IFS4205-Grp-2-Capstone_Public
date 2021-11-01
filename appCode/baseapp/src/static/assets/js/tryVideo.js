    var socket = io('https://127.0.0.1:5000');

    // checking for connection
    socket.on('connect', function() {
        console.log("Connected... ", socket.connected)
    });

    var video = document.getElementById('videoElement');

    if (navigator.mediaDevices.getUserMedia) {
        navigator.mediaDevices.getUserMedia({ video: true })
            .then(function(stream) {
                document.getElementById('videoElement').srcObject = stream
                console.log(document.getElementById('videoElement').srcObject)
                document.getElementById('submitFace').addEventListener('click', () => { getFrame() })
            })
            .catch(function(err0r) {
                console.log(err0r)
                console.log("Something went wrong!");
            });
    }

    // returns a frame encoded in base64
    const getFrame = () => {
        const canvas = document.createElement('canvas');
        canvas.width = document.getElementById('videoElement').videoWidth;
        canvas.height = document.getElementById('videoElement').videoHeight;
        canvas.getContext('2d').drawImage(document.getElementById('videoElement'), 0, 0, 300, 300);
        const data = canvas.toDataURL('image/png');
        document.getElementById('faceValue').setAttribute('value', data);
        document.getElementById('faceRecogForm').submit();
    }