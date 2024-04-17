package com.object.entity;

import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;

public record RestBean<T>(int code, T data, String message) {
    public static <T> RestBean<T> success(T data){
        return new RestBean<>(20000, data, "success");
    }

    public static <T> RestBean<T> success(){
        return success(null);
    }

    public String asJsonString(){
        //JSONWriter.Feature.WriteNulls 保证data就算是null也会进行序列化
        return JSONObject.toJSONString(this, JSONWriter.Feature.WriteNulls);
    }

    public static <T> RestBean<T> failure(int code,String message){
        return new RestBean<>(code, null, message);
    }
}
