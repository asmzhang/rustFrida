package com.asmzhang.testapp;

import android.app.Application;
import android.content.Context;
import android.util.Log;

public class TestAppApplication extends Application {
    private static final String TAG = "TestAppEntry";

    @Override
    protected void attachBaseContext(Context base) {
        Log.i(TAG, "attachBaseContext");
        super.attachBaseContext(base);
        Log.i(TAG, "attachBaseContext done");
    }

    @Override
    public void onCreate() {
        Log.i(TAG, "Application.onCreate enter");
        super.onCreate();
        Log.i(TAG, "Application.onCreate done");
    }
}
