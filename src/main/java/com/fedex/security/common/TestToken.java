package com.fedex.security.common;

import com.fedex.security.exceptions.AuthenticationFailureException;
import com.fedex.security.server.Authenticator;
import com.fedex.security.server.LdapCipherProviderImpl;
import com.fedex.security.server.PkcTokenAuthenticatorImpl;
import com.fedex.security.server.RevocationProviderFactory;
import com.fedex.security.server.ServerCipherProviderFactory;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class TestToken {
	public static void main(String[] args) throws Exception {
		Authenticator authn = PkcTokenAuthenticatorImpl.getInstance();
		ServerCipherProviderFactory.configure(LdapCipherProviderImpl.getInstance());
		RevocationProviderFactory.configure(LdapCipherProviderImpl.getInstance());
		String serviceName = "SECURITY";
		String folderName = "/home/pa609348/SecurityAPI-C/tokens/";
		String token = "";
		File badTokensDir = new File("/home/pa609348/SecurityAPI-C/badtokens");
		File folder = new File("/home/pa609348/SecurityAPI-C/tokens/");
		for (; ; ) {
			File[] filesList = folder.listFiles();
			for (int i = 0; i < filesList.length; i++) {
				FileInputStream fis = null;
				BufferedInputStream bis = null;
				DataInputStream dis = null;
				if (filesList[i].isFile()) {
					System.out.println("File " + filesList[i].getName());
					String fileName = "/home/pa609348/SecurityAPI-C/tokens/" + filesList[i].getName();
					File file = new File(fileName);
					try {
						fis = new FileInputStream(file);
						bis = new BufferedInputStream(fis);
						dis = new DataInputStream(bis);
						while (dis.available() != 0) {
							token = dis.readLine();
						}
					}
					catch (FileNotFoundException e) {
						e.printStackTrace();
					}
					catch (IOException e) {
						e.printStackTrace();
					}
					finally {
						fis.close();
						bis.close();
						dis.close();
					}
					if (doauth(token, "SECURITY")) {
						if (!file.delete()) {
							System.out.println("Failed in deleting the file " + file.getName());
						}
					}
					else {
						if (!file.renameTo(new File(badTokensDir, file.getName()))) {
							System.out.println("File " + file.getName() + " was not successfully moved");
						}
					}
				}
				else {
					if (filesList[i].isDirectory()) {
						System.out.println("Directory " + filesList[i].getName());
					}
				}
			}
			Thread.sleep(5000L);
		}
	}

	private static boolean doauth(String token, String serviceName) {
		boolean flag = false;
		try {
			System.out.println(PkcTokenAuthenticatorImpl.getInstance().authenticate(token, serviceName).getName());
			flag = true;
		}
		catch (AuthenticationFailureException e) {
			System.err.println(e.getReasonCode() + " : " + e.getMessage());
		}
		return flag;
	}
}
