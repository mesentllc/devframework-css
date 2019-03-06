package com.fedex.security.client;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileUtil {
	public static byte[] getBytesFromFile(String filename)
			throws IOException {
		File file = new File(filename);
		long length = file.length();
		if (length > 2147483647L) {
			throw new IOException("File is too large to fit into a byte array.");
		}
		byte[] retval = new byte[(int)length];
		FileInputStream fis = new FileInputStream(file);
		int offset = 0;
		int numread = 0;
		while ((offset < length) && ((numread = fis.read(retval, offset, retval.length - offset)) >= 0)) {
			offset += numread;
		}
		if (offset < length) {
			throw new IOException("Data read doesn't match file length.");
		}
		fis.close();
		return retval;
	}

	public static String getStringFromFile(String filename)
			throws IOException {
		byte[] data = getBytesFromFile(filename);
		return new String(data);
	}

	public static void putBytesToFile(String filename, byte[] content)
			throws IOException {
		FileOutputStream fos = new FileOutputStream(filename);
		fos.write(content);
		fos.close();
	}

	public static String retrieveAbsolutePathofFile(String fileName) {
		String filePath = "";
		File f = new File(fileName);
		filePath = f.getAbsolutePath();
		return filePath;
	}

	public static void copy(String fromFileName, String toFileName)
			throws IOException {
		File fromFile = new File(fromFileName);
		File toFile = new File(toFileName);
		if (!fromFile.exists()) {
			throw new IOException("FileCopy: no such source file: " + fromFileName);
		}
		if (!fromFile.isFile()) {
			throw new IOException("FileCopy: can't copy directory: " + fromFileName);
		}
		if (!fromFile.canRead()) {
			throw new IOException("FileCopy: source file is unreadable: " + fromFileName);
		}
		if (toFile.isDirectory()) {
			toFile = new File(toFile, fromFile.getName());
		}
		String parent = toFile.getParent();
		if (parent == null) {
			parent = System.getProperty("user.dir");
		}
		File dir = new File(parent);
		if (!dir.exists()) {
			throw new IOException("FileCopy: destination directory doesn't exist: " + parent);
		}
		if (dir.isFile()) {
			throw new IOException("FileCopy: destination is not a directory: " + parent);
		}
		if (!dir.canWrite()) {
			throw new IOException("FileCopy: destination directory is unwriteable: " + parent);
		}
		FileInputStream from = null;
		FileOutputStream to = null;
		try {
			from = new FileInputStream(fromFile);
			to = new FileOutputStream(toFile);
			toFile.setReadable(false, false);
			toFile.setReadable(true);
			toFile.setWritable(false, false);
			toFile.setWritable(true);
			toFile.setExecutable(false, false);
			toFile.setExecutable(false);
			byte[] buffer = new byte[4096];
			int bytesRead;
			while ((bytesRead = from.read(buffer)) != -1) {
				to.write(buffer, 0, bytesRead);
			}
			return;
		}
		finally {
			if (from != null) {
				try {
					from.close();
				}
				catch (IOException e) {
				}
			}
			if (to != null) {
				try {
					to.close();
				}
				catch (IOException e) {
				}
			}
		}
	}

	public static boolean deleteDir(File dir) {
		if (dir.isDirectory()) {
			String[] children = dir.list();
			for (String item : children) {
				boolean success = deleteDir(new File(dir, item));
				if (!success) {
					return false;
				}
			}
		}
		return dir.delete();
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\client\FileUtil.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */