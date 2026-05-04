const fs = require("fs");
const path = require("path");

exports.uploadApk = (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: "No file uploaded" });
    }
    res.status(200).json({
      success: true,
      message: "APK uploaded successfully",
      filename: req.file.filename,
    });
  } catch (error) {
    console.error("APK Upload Error:", error);
    res.status(500).json({ success: false, message: "Failed to upload APK" });
  }
};

exports.downloadLatestApk = (req, res) => {
  const apkPath = path.join(__dirname, "..", "uploads", "apk", "studyvault.apk");
  if (fs.existsSync(apkPath)) {
    res.download(apkPath, "StudyvaultCampus.apk");
  } else {
    res.status(404).json({ message: "APK file not found on server" });
  }
};
