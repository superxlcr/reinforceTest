package com.example.superxlcr.reinforcetest;

import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * @author liangmingrui
 *         2017/8/24 19:48
 */

public class RefInvoke {

    private static final String TAG = RefInvoke.class.getSimpleName();

    public static Object invokeStaticMethod(String className, String methodName, Class[] pareType, Object[] pareValues) {
        try {
            Class clazz = Class.forName(className);
            Method method = clazz.getDeclaredMethod(methodName, pareType);
            method.setAccessible(true);
            return method.invoke(null, pareValues);
        } catch (Exception e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }
        return null;
    }

    public static Object invokeMethod(String className, String methodName, Object object, Class[] pareType, Object[] pareValues) {
        try {
            Class clazz = Class.forName(className);
            Method method = clazz.getDeclaredMethod(methodName, pareType);
            method.setAccessible(true);
            return method.invoke(object, pareValues);
        } catch (Exception e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }
        return null;
    }

    public static Object getFieldObject(String className, String fieldName, Object object) {
        try {
            Class clazz = Class.forName(className);
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
            return field.get(object);
        } catch (Exception e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }
        return null;
    }

    public static void setFieldObject(String className, String fieldName, Object object, Object value) {
        try {
            Class clazz = Class.forName(className);
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(object, value);
        } catch (Exception e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }

}