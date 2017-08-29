package com.example.superxlcr.reinforcetest;

import android.app.Application;
import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.ArrayMap;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import dalvik.system.DexClassLoader;

/**
 * @author liangmingrui
 *         2017/8/28 14:50
 */

public class ReinforceApplication extends Application {

    private static final String TAG = ReinforceApplication.class.getSimpleName();

    private static final String ACTIVITY_THREAD = "android.app.ActivityThread";
    private static final String LOADED_APK = "android.app.LoadedApk";

    private static final String APPLICATION_CLASS_NAME = "APPLICATION_CLASS_NAME";

    private String mApkFileName;
    private String mOdexPath;
    private String mLibPath;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        initDexEnvironment();
        decryptDex();
        replaceDexLoader();
    }

    @Override
    public void onCreate() {
        String appClassName = null;
        // 获取Application名字
        try {
            ApplicationInfo ai = this.getPackageManager()
                    .getApplicationInfo(this.getPackageName(),
                            PackageManager.GET_META_DATA);
            Bundle bundle = ai.metaData;
            if (bundle != null && bundle.containsKey(APPLICATION_CLASS_NAME)) {
                appClassName = bundle.getString(APPLICATION_CLASS_NAME);
            } else {
                return;
            }
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }
        Log.i(TAG, appClassName);

        Object sCurrentActivityThread = RefInvoke.invokeStaticMethod(
                ACTIVITY_THREAD, "currentActivityThread",
                new Class[]{}, new Object[]{});
        Object mBoundApplication = RefInvoke.getFieldObject(
                ACTIVITY_THREAD, "mBoundApplication", sCurrentActivityThread);
        Object info = RefInvoke.getFieldObject(
                ACTIVITY_THREAD + "$AppBindData", "info", mBoundApplication);
        // 把当前进程的mApplication 设置成null
        RefInvoke.setFieldObject(LOADED_APK, "mApplication", info, null);
        // 删除oldApplication
        Object oldApplication = RefInvoke.getFieldObject(
                ACTIVITY_THREAD, "mInitialApplication", sCurrentActivityThread);
        ArrayList<Application> mAllApplications = (ArrayList<Application>) RefInvoke
                .getFieldObject(ACTIVITY_THREAD, "mAllApplications", sCurrentActivityThread);
        mAllApplications.remove(oldApplication);

        ApplicationInfo appInfoInLoadedApk = (ApplicationInfo) RefInvoke
                .getFieldObject(LOADED_APK, "mApplicationInfo", info);
        ApplicationInfo appInfoInAppBindData = (ApplicationInfo) RefInvoke
                .getFieldObject(ACTIVITY_THREAD + "$AppBindData", "appInfo", mBoundApplication);
        appInfoInLoadedApk.className = appClassName;
        appInfoInAppBindData.className = appClassName;
        // 执行 makeApplication（false,null），此功能需要把当前进程的mApplication 设置成null
        Application app = (Application) RefInvoke.invokeMethod(
                LOADED_APK, "makeApplication", info,
                new Class[]{boolean.class, Instrumentation.class},
                new Object[]{false, null});
        RefInvoke.setFieldObject(ACTIVITY_THREAD, "mInitialApplication", sCurrentActivityThread,
                app);

        ArrayMap mProviderMap = (ArrayMap) RefInvoke
                .getFieldObject(ACTIVITY_THREAD, "mProviderMap", sCurrentActivityThread);
        Iterator it = mProviderMap.values().iterator();
        while (it.hasNext()) {
            Object providerClientRecord = it.next();
            Object localProvider = RefInvoke
                    .getFieldObject(ACTIVITY_THREAD + "$ProviderClientRecord", "mLocalProvider",
                            providerClientRecord);
            RefInvoke.setFieldObject("android.content.ContentProvider", "mContext", localProvider,
                    app);
        }

        Log.i(TAG, "app:" + app);
        app.onCreate();
    }

    private void initDexEnvironment() {
        mApkFileName = getApplicationInfo().dataDir + "/real.apk";
        mOdexPath = getApplicationInfo().dataDir + "/odex";
        File odexDir = new File(mOdexPath);
        if (!odexDir.exists()) {
            odexDir.mkdir();
        }
        mLibPath = getApplicationInfo().nativeLibraryDir;
    }

    private void decryptDex() {
        byte[] dex = readDexFromApk();
        if (dex != null) {
            byte[] realApkBytes = decryption(dex);
            if (realApkBytes != null) {
                try {
                    File realApk = new File(mApkFileName);
                    if (realApk.exists()) {
                        realApk.delete();
                    }
                    realApk.createNewFile();
                    FileOutputStream fos = new FileOutputStream(realApk);
                    fos.write(realApkBytes);
                    fos.flush();
                    fos.close();
                } catch (IOException e) {
                    Log.e(TAG, Log.getStackTraceString(e));
                }
            }
        }
    }

    private byte[] readDexFromApk() {
        File sourceApk = new File(getPackageCodePath());
        try {
            ZipInputStream zis = new ZipInputStream(new FileInputStream(sourceApk));
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().equals("classes.dex")) {
                    byte[] bytes = new byte[1024];
                    int len;
                    while ((len = zis.read(bytes)) != -1) {
                        baos.write(bytes, 0, len);
                        baos.flush();
                    }
                    return baos.toByteArray();
                }
            }
            zis.close();
            return null;
        } catch (IOException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return null;
        }
    }

    private byte[] decryption(byte[] dex) {
        int totalLen = dex.length;
        byte[] realApkLenBytes = new byte[4];
        System.arraycopy(dex, totalLen - 4, realApkLenBytes, 0, 4);
        ByteArrayInputStream bais = new ByteArrayInputStream(realApkLenBytes);
        DataInputStream ins = new DataInputStream(bais);
        int realApkLen;
        try {
            realApkLen = ins.readInt();
        } catch (IOException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return null;
        }
        byte[] realApkBytes = new byte[realApkLen];
        System.arraycopy(dex, totalLen - 4 - realApkLen, realApkBytes, 0, realApkLen);
        return realApkBytes;
    }

    private void replaceDexLoader() {
        Object sCurrentActivityThread = RefInvoke
                .invokeStaticMethod(ACTIVITY_THREAD, "currentActivityThread", null, null);
        String packageName = getPackageName();
        ArrayMap mPackages = (ArrayMap) RefInvoke
                .getFieldObject(ACTIVITY_THREAD, "mPackages", sCurrentActivityThread);
        WeakReference weakReference = (WeakReference) mPackages.get(packageName);
        Object loadedApk = weakReference.get();
        ClassLoader mClassLoader = (ClassLoader) RefInvoke
                .getFieldObject(LOADED_APK, "mClassLoader", loadedApk);
        DexClassLoader dexClassLoader = new DexClassLoader(mApkFileName, mOdexPath, mLibPath,
                mClassLoader);
        RefInvoke.setFieldObject(LOADED_APK, "mClassLoader", loadedApk, dexClassLoader);
    }
}
