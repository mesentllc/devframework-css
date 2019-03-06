package com.fedex.security.common;

import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URL;
import java.util.Date;
import java.util.Enumeration;
import java.util.Properties;

public class FileLoader {
	private static final FedExLoggerInterface logger = FedExLogger.getLogger(FileLoader.class.getName());

	public static Properties getFileAsProperties(String fileName) {
		InputStream is = null;
		Properties props = null;
		if ((fileName != null) && (fileName.length() > 0)) {
			try {
				is = getFileAsInputStream(fileName);
				if (is != null) {
					props = new Properties();
					props.load(is);
					is.close();
					is = null;
				}
			}
			catch (IOException e) {
				logger.fatal(new FedExLogEntry("Error loading props file [" + fileName + "]"), e);
				props = null;
			}
			finally {
				try {
					if (is != null) {
						is.close();
					}
				}
				catch (IOException ioe) {
					logger.warn(new FedExLogEntry("Error closing file input stream in finally"), ioe);
				}
			}
		}
		else {
			throw new IllegalArgumentException("FileLoader.getFileAsProperties - fileName param is null");
		}
		if (props == null) {
			throw new RuntimeException("Could not load [" + fileName + "]" + " as a Properties object.");
		}
		return props;
	}

	public static InputStream getFileAsInputStream(String fileName) {
		InputStream is = null;
		if ((fileName != null) && (fileName.length() > 0)) {
			try {
				is = null;
				File f = new File(fileName);
				if ((f != null) && (f.exists())) {
					is = new FileInputStream(f);
					logger.debug("Loaded file: " + f.getAbsolutePath());
				}
				else {
					is = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileName);
					if (is != null) {
						URL url = Thread.currentThread().getContextClassLoader().getResource(fileName);
						if (url != null) {
							logger.debug("Loaded file: " + url.getFile());
						}
						else {
							logger.debug("SHOULD NEVER HAPPEN: getResourceAsStream loaded file '" + fileName + "', but getResource could not find it :(");
						}
					}
				}
			}
			catch (IOException e) {
				logger.fatal(new FedExLogEntry("Error loading file [" + fileName + "]"), e);
				is = null;
			}
		}
		else {
			throw new IllegalArgumentException("FileLoader.getFileAsInputStream - fileName param is null");
		}
		if (is == null) {
			alwaysLogFiles(fileName);
			throw new RuntimeException("Could not load [" + fileName + "]" + " as an input stream.");
		}
		return is;
	}

	public static File getFile(String fileName) {
		File file = null;
		if ((fileName != null) && (fileName.length() > 0)) {
			File f = new File(fileName);
			if ((f != null) && (f.exists())) {
				file = f;
			}
			else {
				URL u = Thread.currentThread().getContextClassLoader().getResource(fileName);
				if (u != null) {
					file = new File(u.getFile());
				}
			}
		}
		else {
			throw new IllegalArgumentException("FileLoader.getFile - fileName param is null");
		}
		if (file != null) {
			logger.debug("Loaded file: " + file.getAbsolutePath());
		}
		else {
			alwaysLogFiles(fileName);
		}
		return file;
	}

	public synchronized Object readObjectFromDisk(String fileName) {
		ObjectInputStream ois = null;
		Object o = null;
		try {
			File f = new File(fileName);
			if (f.exists()) {
				ois = new ObjectInputStream(new FileInputStream(f));
				o = ois.readObject();
				ois.close();
			}
			return o;
		}
		catch (Exception e) {
			logger.fatal(new FedExLogEntry("Error reading cache from disk filename=" + fileName), e);
		}
		finally {
			try {
				if (ois != null) {
					ois.close();
				}
			}
			catch (Exception e2) {
				logger.warn(new FedExLogEntry("Error closing object input stream filename=" + fileName), e2);
			}
		}
		return o;
	}

	public synchronized void saveObjectToDisk(String fileName, Object o) {
		ObjectOutputStream oos = null;
		try {
			oos = new ObjectOutputStream(new FileOutputStream(fileName, false));
			oos.writeObject(o);
			oos.flush();
			oos.close();
			return;
		}
		catch (Exception e) {
			logger.fatal(new FedExLogEntry("Error saving cache to disk filename=" + fileName), e);
		}
		finally {
			try {
				if (oos != null) {
					oos.close();
				}
			}
			catch (Exception e2) {
				logger.warn(new FedExLogEntry("Error closing object output stream filename=" + fileName), e2);
			}
		}
	}

	public static void alwaysLogFiles(String fileName) {
		StringBuilder sb = new StringBuilder();
		if ((fileName != null) && (fileName.length() > 0)) {
			File f = new File(fileName);
			if ((f != null) && (f.exists())) {
				sb.append("Found '" + fileName);
				sb.append("' at '" + f.getAbsolutePath());
				sb.append("', isFile = " + (f.isFile() ? "Y" : "N"));
				sb.append(", canRead = " + (f.canRead() ? "Y" : "N"));
				sb.append(", canWrite = " + (f.canWrite() ? "Y" : "N"));
				sb.append(", lastModified = " + new Date(f.lastModified()));
				logger.always(sb.toString());
			}
			else {
				logger.always("java.class.path='" + System.getProperty("java.class.path") + "'");
				try {
					Enumeration<URL> urlEnum = Thread.currentThread().getContextClassLoader().getResources(fileName);
					if ((urlEnum != null) && (urlEnum.hasMoreElements())) {
						logger.always("No files found for " + fileName);
					}
					while (urlEnum.hasMoreElements()) {
						URL url = urlEnum.nextElement();
						f = new File(url.getFile());
						sb.append("Found '" + fileName);
						sb.append("' at '" + f.getAbsolutePath());
						sb.append("', isFile = " + (f.isFile() ? "Y" : "N"));
						sb.append(", canRead = " + (f.canRead() ? "Y" : "N"));
						sb.append(", canWrite = " + (f.canWrite() ? "Y" : "N"));
						sb.append(", lastModified = " + new Date(f.lastModified()));
						logger.always(sb.toString());
						continue;
					}
				}
				catch (IOException e) {
					logger.always("Unable to list URL entries for file " + fileName, e);
				}
			}
		}
		else {
			throw new IllegalArgumentException("FileLoader.alwaysLogFiles - fileName param is null");
		}
		sb.setLength(0);
		sb = null;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\common\FileLoader.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */