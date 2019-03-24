/*
Name:   PwnedPasswords Checker 
Date:   24.03.2018
Author: Saadat Baig <mass1ve_err0r>
*/

import java.net.*;
import java.io.*;
import java.util.*;
import java.security.*;
import java.math.*;

class pwned_password_checker {

    public static Console console = System.console();

    public static String trigger_start() {
        System.out.println("PwnedPassword Checker / <mass1ve_err0r>");        
        char parr[] = console.readPassword("Enter your password: ");    // password entry is hidden!
        String inputstring = new String(parr);
        int pw_length = inputstring.length();
        System.out.println("Password length:    " + pw_length);
        return inputstring;
    }

    public static String sha1gen(String input_trigger) {
        String sha1 = "";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.reset();
            digest.update(input_trigger.getBytes("UTF-8"));
            sha1 = String.format("%040x", new BigInteger(1, digest.digest()));
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (UnsupportedEncodingException e) {
            return null;
        }
        return sha1;
    }
    
    public static void check_password(String hashedpass_uncut) {
        String sha1hash = hashedpass_uncut.toUpperCase();   //initialize as caps.
        String hash_short =  sha1hash.substring(0, Math.min(sha1hash.length(), 5)); //get first five chars of SHA-1 String with precautionary 0-catcher.
        String sha1cut = sha1hash.substring(5, sha1hash.length());  // remove first 5 chars of SHA-1 and save as own var
        System.out.println("Generated SHA-1:    " + sha1hash);
        System.out.println("Padded (5) SHA-1:   " + sha1cut);

        String adress = "https://api.pwnedpasswords.com/range/" + hash_short;
        
        try {
        URL url = new URL(adress);
        BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()));

        List<String> receivedhashlist = new ArrayList<>();  // Dynamic list with hashes only
        List<String> receivedhashlist_full = new ArrayList<>(); // Dynamic list with their occurance matching index
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            receivedhashlist.add(inputLine.substring(0, inputLine.indexOf(":")));
            receivedhashlist_full.add(inputLine.substring(inputLine.indexOf(":") +1,inputLine.length()));
        }

        // -- SEARCH AND FIND
        if (receivedhashlist.contains(sha1cut) == true){
            int index = receivedhashlist.indexOf(sha1cut);
            String occurance_count = receivedhashlist_full.get(index);
            System.out.println("Result: Password Found on Server !");
            System.out.println("!-- Please change your password --!");
            System.out.println("Occurance:  " + occurance_count);
        } else {
            System.out.println("Result: Password was NOT found on the Server.");
        }

        in.close(); // DO NOT FORGET THY CLOSURE
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        check_password(sha1gen(trigger_start()));
    }
}
