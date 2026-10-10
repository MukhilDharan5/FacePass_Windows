Offline models are bundled in this workspace and copied next to the binaries.

| Model | Source | License | SHA256 |
|---|---|---|---|
| YuNet 2023mar | [OpenCV Zoo](https://github.com/opencv/opencv_zoo/tree/main/models/face_detection_yunet) | MIT (LICENSE-YuNet.txt) | 8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4 |
| SFace 2021dec | [OpenCV Zoo](https://github.com/opencv/opencv_zoo/tree/main/models/face_recognition_sface) | Apache 2.0 (LICENSE-SFace.txt) | 0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79 |

OpenCV 4.12.0 executes these ONNX graphs through its mature CPU DNN backend, avoiding a second inference dependency. Detection produces five landmarks; SFace aligns the face and produces a 128-dimensional normalized embedding. Recognition uses median cosine similarity over seven enrollment embeddings, never raw-frame comparison. Thresholds require validation on the actual camera and intended population; the provided defaults do not establish a security assurance level. Models and template format are versioned together; changing models requires re-enrollment.
