# Camera access, face recognition, timekeeping
from base64 import encode
import cv2, face_recognition
RECOG_DURATION = 10     # 10 seconds for face recognition
SCALAR_X = 0.25         # scaling of frame x coord
SCALAR_Y = 0.25         # scaling of frame y coord

def compareVidFeedDB(vidPicture, profilePicture):
    """Compares between profile image linked to database and the current video feed
    
    :param vidPicture: picture generated from video feed
    :param profilePicture: picture generated from linked database
    :return matches: true if both images can be recognised similarly, false otherwise
    """
    encodedImg = prepPicture(profilePicture, True)
    encodedVid = prepPicture(vidPicture, False)
    matches = False
    for encodeFace in encodedVid:
        matches = face_recognition.compare_faces([encodedImg], encodeFace)
    if type(matches) is not bool: 
        matches = matches[0]
    if matches: print("Face is recognised :)")
    else: print("Face not identified :(")
    return matches


def prepPicture(profilePicture, type):
    """Loads image path, converts it into RGB and encodes it
    
    :param profilePicture: path to picture
    :param type: True if is database image, false for videofeed
    :return EncodedImg: a cv2 specific encoding of the image
    """
    # Import image
    img = None
    img = face_recognition.load_image_file(profilePicture)
    if not type:
        img = cv2.resize(img, None, fx=SCALAR_X, fy=SCALAR_Y, interpolation=cv2.INTER_AREA)
    # Loading images into rgb
    img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    # Encode the image
    if type:
        EncodedImg = face_recognition.face_encodings(img)[0]
        return EncodedImg
    else:
        EncodedImg = face_recognition.face_encodings(img)
        return EncodedImg

