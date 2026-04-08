package com.asmzhang.testapp;

import androidx.appcompat.app.AppCompatActivity;

import android.util.Log;
import android.os.Bundle;
import android.widget.TextView;

import com.asmzhang.testapp.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "TestApp";

    // Used to load the 'testapp' library on application startup.
    static {
        Log.i(TAG, "loading native library: testapp");
        System.loadLibrary("testapp");
        Log.i(TAG, "native library loaded");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "onCreate enter");

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;
        Log.i(TAG, "calling stringFromJNI()");
        String text = stringFromJNI();
        Log.i(TAG, "stringFromJNI() returned: " + text);
        tv.setText(text);
        Log.i(TAG, "sampleText updated in onCreate");
    }

    @Override
    protected void onResume() {
        super.onResume();
        Log.i(TAG, "onResume");
    }

    /**
     * A native method that is implemented by the 'testapp' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
}
