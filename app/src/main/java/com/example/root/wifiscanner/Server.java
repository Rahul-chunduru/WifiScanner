package com.example.root.wifiscanner;

import android.Manifest;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.provider.Settings;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Server extends AppCompatActivity {
    TextView mainText , side;
    WifiManager mainWifi;
    WifiReceiver receiverWifi;
    List<ScanResult> wifiList;
    StringBuilder sb = new StringBuilder();
    Button b ;
    private static final int PERMISSIONS_REQUEST_CODE_ACCESS_COARSE_LOCATION = 1001;
    @Override
    public void onCreate(Bundle savedInstanceState)  {

        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main2);


        mainText = (TextView) findViewById(R.id.mainText);
        mainText.setMovementMethod(new ScrollingMovementMethod());
        side = findViewById(R.id.side) ;
        // addContentView(mainText,new ViewGroup.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));


        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED){
            requestPermissions(new String[]{Manifest.permission.ACCESS_COARSE_LOCATION}, PERMISSIONS_REQUEST_CODE_ACCESS_COARSE_LOCATION);


        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (Settings.System.canWrite(this.getApplicationContext())) {

            } else {
                Intent intent = new Intent(android.provider.Settings.ACTION_MANAGE_WRITE_SETTINGS);
                intent.setData(Uri.parse("package:" + this.getPackageName()));
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(intent);
            }
        }


        b = findViewById(R.id.buttscan) ;
        b.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
//                mainWifi.setWifiEnabled(false); // turn off Wifi
//                WifiConfiguration myConfig = new WifiConfiguration();
//                myConfig.SSID = "naruto"; // SSID name of netwok
//                myConfig.preSharedKey = "picassoder"; // password for network
//                myConfig.allowedKeyManagement.set(4); // 4 is for KeyMgmt.WPA2_PSK which is not exposed by android KeyMgmt class
//                myConfig.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN); // Set Auth Algorithms to open
//                try {
//                    mainText.append("Must be on");
//                    Method method = mainWifi.getClass().getMethod("setWifiApEnabled", WifiConfiguration.class, boolean.class);
//                    boolean f = (boolean) method.invoke(mainWifi, myConfig, true);
//                    mainText.append("\n" + f);
//                } catch (Exception e) {
//                    mainText.setText("ERROR:\n");
//                    mainText.append(e.getLocalizedMessage());
//                    e.printStackTrace();
//                }
//                mainText.append("\n " + isApOn() + "\n");
                EditText edit = findViewById(R.id.plain) ;
                String key_data = edit.getText().toString() ;
                int l = 16 - key_data.length() ;
                for(int i = 0 ; i < l ; i++) key_data = "0" + key_data ;
                byte[] plain = key_data.toString().getBytes() ;
                byte[] key = "0000000000001234".getBytes() ;
                try {
                    byte[] encrypted = encrypt(key, plain);
                    byte[] decrypted = decrypt(key , encrypted)  ;
                    mainText.append( "Encrypted data :" + new String(encrypted) +  " \n");
                    mainText.append( "Decrypted data :" +new String(decrypted) +  " \n");
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                }
            }
        });

    }

    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, 0, 0, "Refresh");
        return super.onCreateOptionsMenu(menu);
    }
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        mainWifi.startScan();
        mainText.setText("Starting Scan");
        side.setText("");
        // do Your Work Here
        return super.onOptionsItemSelected(item);
    }

    protected void onPause() {
        unregisterReceiver(receiverWifi);
        super.onPause();
    }

    protected void onResume() {
        registerReceiver(receiverWifi, new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION));
        super.onResume();
    }
    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions,
                                           int[] grantResults) {
        if (requestCode == PERMISSIONS_REQUEST_CODE_ACCESS_COARSE_LOCATION
                && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            Toast.makeText( getApplicationContext() , "Location ok" , Toast.LENGTH_SHORT).show();

            // TODO: What you want to do when it works or maybe .PERMISSION_DENIED if it works better
        }
    }

    // Broadcast receiver class called its receive method
    // when number of wifi connections changed

    class WifiReceiver extends BroadcastReceiver {

        // This method call when number of wifi connections changed
        public void onReceive(Context c, Intent intent) {

            sb = new StringBuilder();
            wifiList = mainWifi.getScanResults();
            side.setText("\n        Number Of Wifi connections :"+wifiList.size()+"\n\n");

            for(int i = 0; i < wifiList.size(); i++){

                sb.append("        " + new Integer(i+1).toString() + ". ");
                sb.append( wifiList.get(i).SSID + " - " + wifiList.get(i).BSSID);
                sb.append("\n\n");
            }

            mainText.setText(sb);
        }

    }
    // hotspot
    public boolean isApOn() {
        try {
            Method method = mainWifi.getClass().getDeclaredMethod("isWifiApEnabled");
            method.setAccessible(true);
            return (Boolean) method.invoke(mainWifi);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
    /// for encryption
    private static byte[] parseHexBinary(String s)
            throws IllegalArgumentException {
        if (s == null) {
            return new byte[0];
        }
        s = s.trim();
        int length = s.length();

        if (length % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string length.");
        }

        byte[] result = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            result[i/2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        }
        return result;
    }
    private static byte[] encrypt(byte[] raw, byte[] clear) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = cipher.doFinal(clear);
        return encrypted;
    }

    private static byte[] decrypt(byte[] raw, byte[] encrypted) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return decrypted;
    }
}
