const fs = require("fs");
const path = require("path");

const getConfigPath = () => path.join(__dirname, "..", "uploads", "apk_config.json");

exports.uploadApk = (req, res) => {
  try {
    const { apkUrl } = req.body;
    if (!apkUrl) {
      return res.status(400).json({ success: false, message: "No Google Drive URL provided" });
    }

    // Ensure uploads directory exists
    const uploadDir = path.join(__dirname, "..", "uploads");
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }

    // Save the URL to a JSON config file
    fs.writeFileSync(getConfigPath(), JSON.stringify({ apkUrl }), 'utf-8');

    res.status(200).json({
      success: true,
      message: "APK Link updated successfully",
      apkUrl,
    });
  } catch (error) {
    console.error("APK Link Update Error:", error);
    res.status(500).json({ success: false, message: "Failed to update APK link" });
  }
};

exports.downloadLatestApk = (req, res) => {
  try {
    const configPath = getConfigPath();
    if (fs.existsSync(configPath)) {
      const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      if (config.apkUrl) {
        let downloadUrl = config.apkUrl;
        
        // Optionally convert Google Drive shareable link to a direct download link
        // Example shareable link: https://drive.google.com/file/d/1A2B3C4D5E6F7G8H9I0J/view?usp=sharing
        const driveRegex = /https:\/\/drive\.google\.com\/file\/d\/([a-zA-Z0-9_-]+)\/view/;
        const match = downloadUrl.match(driveRegex);
        if (match && match[1]) {
          downloadUrl = `https://drive.google.com/uc?export=download&id=${match[1]}`;
        }

        return res.redirect(downloadUrl);
      }
    }
    res.status(404).json({ message: "APK link not configured on server" });
  } catch (error) {
    console.error("APK Download Error:", error);
    res.status(500).json({ message: "Failed to process APK download" });
  }
};
