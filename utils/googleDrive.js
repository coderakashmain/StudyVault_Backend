const path = require("path");
const fs = require("fs");
const mime = require("mime");
const { google } = require("googleapis");

const oauth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  process.env.REDIRECT_URI
);

oauth2Client.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });

const drive = google.drive({
  version: "v3",
  auth: oauth2Client,
});

async function findFolderupload(folderName) {
  try {
    const response = await drive.files.list({
      q: `mimeType='application/vnd.google-apps.folder' and name='${folderName}' and trashed=false`,
      fields: "files(id, name)",
      spaces: "drive",
    });

    const folders = response.data.files;
    if (folders.length > 0) {
      // Folder exists, return its ID
      return folders[0].id;
    } else {
      // Folder doesn't exist, return null
      return null;
    }
  } catch (error) {
    console.error("Error finding folder on Google Drive:", error);
    throw error;
  }
}

async function createDriveFolder(folderName) {
  try {
    const fileMetadata = {
      name: folderName,
      mimeType: "application/vnd.google-apps.folder",
    };

    const response = await drive.files.create({
      resource: fileMetadata,
      fields: "id",
    });

    // console.log('Folder created on Google Drive with ID:', response.data.id);
    return response.data.id; // Return the folder ID
  } catch (error) {
    console.error("Error creating folder on Google Drive:", error);
    throw error;
  }
}

async function uploadWithRetry(fn, retries = 3) {
  try {
    return await fn();
  } catch (err) {
    if (retries > 0 && err.code === "ECONNRESET") {
     
      return uploadWithRetry(fn, retries - 1);
    }
    throw err;
  }
}


async function uploadFileToDrive(filename, folderId) {
  try {
    const filePath = path.join(__dirname, "uploads", filename); // File saved temporarily in uploads folder
    const fileMetadata = {
      name: filename, // Use the uploaded file's name
      parents: [folderId],
    };
    if (!fs.existsSync(filePath)) {
      throw new Error("File not found at path: " + filePath);
    }

   

    const media = {
      mimeType: "application/pdf", // Assuming the file is a PDF, adjust if needed
      body: fs.createReadStream(filePath),
    };

 const response = await uploadWithRetry(() =>
  drive.files.create(
    {
      resource: fileMetadata,
      media,
      fields: "id",
    },
    { uploadType: "resumable" }
  )
);


    const fileId = response.data.id;

    await drive.permissions.create({
      fileId: fileId,
      resource: {
        role: "reader",
        type: "anyone",
      },
    });

    // console.log('File uploaded successfully to Google Drive. File ID:', fileId);

    return response.data.id; // Return Google Drive file ID
  } catch (error) {
    console.error("Error uploading file to Google Drive:", error);
    throw error;
  }
}

async function uploadFileToDrivett(filename, folderId) {
  try {
    const filePath = path.join(__dirname, "uploads", filename);
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    const mimeType = mime.getType(filePath) || "application/octet-stream";
    const fileMetadata = {
      name: filename,
      parents: [folderId],
    };

    const media = {
      mimeType,
      body: fs.createReadStream(filePath),
    };

    const response = await drive.files.create({
      resource: fileMetadata,
      media: media,
      fields: "id",
    });

    const fileId = response.data.id;

    await drive.permissions.create({
      fileId,
      resource: {
        role: "reader",
        type: "anyone",
      },
    });

    return fileId;
  } catch (error) {
    console.error("Error uploading file to Google Drive:", error);
    throw error;
  }
}

async function findFolder(folderName, parentFolderId = "root") {
  try {
    const response = await drive.files.list({
      q: `name = '${folderName}' and mimeType = 'application/vnd.google-apps.folder' and '${parentFolderId}' in parents`,
      fields: "files(id, name)",
    });

    const folder = response.data.files[0];
    if (!folder) {
      console.log(
        `Folder "${folderName}" not found in parent "${parentFolderId}".`
      );
      return null;
    }

    return folder.id; // Return the folder ID
  } catch (error) {
    console.error("Error finding folder on Google Drive:", error);
    throw error;
  }
}

async function findNestedFolder(folderPath) {
  const folderNames = folderPath.split("/"); // Split the folder path into parts
  let currentParentId = "root"; // Start from the root directory

  for (const folderName of folderNames) {
    const folderId = await findFolder(folderName, currentParentId);
    if (!folderId) {
      console.log(`Folder "${folderName}" does not exist.`);

      // If folder doesn't exist, attempt to clean up the "uploads" folder
      await deleteTempFiles();
      return null; // Stop if any folder in the path is not found
    }
    currentParentId = folderId; // Move into the found folder
  }

  return currentParentId; // Return the ID of the final folder in the path
}

// Function to clean up the temporary files in the uploads directory
async function deleteTempFiles() {
  const uploadFolderPath = path.join(__dirname, "uploads");

  try {
    const files = await fs.promises.readdir(uploadFolderPath);

    for (const file of files) {
      const filePath = path.join(uploadFolderPath, file);
      await fs.promises.unlink(filePath); // Delete the file
      // console.log("Deleted file:", filePath);
    }
  } catch (error) {
    console.error("Error deleting files in uploads folder:", error);
  }
}

module.exports = {
  findFolderupload,
  uploadFileToDrive,
  uploadFileToDrivett,
  createDriveFolder,
  findNestedFolder,
  findFolder,
  deleteTempFiles,
};
