package com.dawnnnnnn.wechat_cloud_function_hook

import android.R.attr.classLoader
import android.app.ActivityManager
import android.content.Context
import android.os.Process
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import io.ktor.application.*
import io.ktor.features.ContentNegotiation
import io.ktor.features.StatusPages
import io.ktor.gson.gson
import io.ktor.http.HttpStatusCode
import io.ktor.request.receive
import io.ktor.response.respond
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import kotlin.concurrent.thread


data class CallWXRequest(val appid: String, val jsapi_name: String, val data: String)

class WeChatHook : IXposedHookLoadPackage, IXposedHookZygoteInit {

    private var serverStarted = false
    private var callWXAsyncRequestCounter = 0
    private var callAppId: String? = null
    private val hookedAppIds = mutableSetOf<String>()
    private val label = "[WX-FaaS-HOOK]"
    private val requestLabel = "[WX-FaaS-HOOK-Network]"
    private val logList = mutableListOf<String>()
    private val maxLogSize = 1500
    private var appBrandCommonBindingJniInstance: Any? = null

    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {

    }

    private fun setupHooks(lpparam: XC_LoadPackage.LoadPackageParam) {
        // Target the AppBrand processes
        if (!lpparam.processName.contains("com.tencent.mm:appbrand")) return

        log("$label Active in process ${lpparam.processName}. Waiting for UI to trigger hooks...")

        // 1. Hook the base Activity onCreate.
        // This is the "Frida trigger": once the mini-program UI exists, the engine MUST be loaded.
        XposedHelpers.findAndHookMethod(
            "android.app.Activity",
            lpparam.classLoader,
            "onCreate",
            android.os.Bundle::class.java,
            object : XC_MethodHook() {
                private var hooksApplied = false

                override fun afterHookedMethod(param: MethodHookParam) {
                    val activity = param.thisObject as android.app.Activity
                    val activityName = activity.javaClass.name

                    // Check if this is the AppBrandUI (the mini-program container)
                    if (activityName.contains("com.tencent.mm.plugin.appbrand.ui.AppBrandUI") && !hooksApplied) {
                        val realClassLoader = activity.classLoader
                        log("$label [UI DETECTED] $activityName found. Injecting hooks now...")

                        if (injectRealHooks(realClassLoader)) {
                            hooksApplied = true // Only apply once per process
                        }
                    }
                }
            }
        )
    }

    private fun injectRealHooks(classLoader: ClassLoader): Boolean {
        var success = false
        try {
            // --- HOOK 1: REQUEST (nativeInvokeHandler) ---
            // As per your JADX screenshot: String, String, String, int, boolean, int, int
            XposedHelpers.findAndHookMethod(
                "com.tencent.mm.appbrand.commonjni.AppBrandCommonBindingJni",
                classLoader,
                "nativeInvokeHandler",
                String::class.java,           // jsapi_name
                String::class.java,           // data
                String::class.java,           // extra
                "int",                        // callbackId
                "boolean",                    // isSync
                "int",                        // arg6
                "int",                        // arg7
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        appBrandCommonBindingJniInstance = param.thisObject
                        val api = param.args[0] as String
                        val data = param.args[1] as String
                        log("[REQ] -> API: $api | Data: $data")
                    }
                }
            )
            log("$label Hooked Request successfully.")
            success = true
        } catch (e: Throwable) {
            log("$label Failed to hook Request: ${e.message}")
        }

        try {
            // --- HOOK 2: RESPONSE (invokeCallbackHandler) ---
            // Your JADX shows 3 params: (int, String, String)
            XposedHelpers.findAndHookMethod(
                "com.tencent.mm.appbrand.commonjni.AppBrandJsBridgeBinding",
                classLoader,
                "invokeCallbackHandler",
                "int",              // callbackId
                String::class.java, // result
                String::class.java, // extra
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val id = param.args[0]
                        val res = param.args[1]
                        log("[RES] <- ID: $id | Result: $res")
                    }
                }
            )
            log("$label Hooked Response successfully.")
            success = true
        } catch (e: Throwable) {
            log("$label Failed to hook Response: ${e.message}")
        }

        return success
    }

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName == "com.tencent.mm") {
            log("$label Found app ${lpparam.packageName} with processName: ${lpparam.processName}")
            setupHooks(lpparam)
        }
    }

    private fun startServerIfNeeded() {
        if (!serverStarted) {
            startServer()
            serverStarted = true
        }
    }

//    private fun hookInvokeHandlersIfNeeded(
//        lpparam: XC_LoadPackage.LoadPackageParam,
//        appId: String
//    ) {
//        if (!hookedAppIds.contains(appId)) {
//            hookInvokeHandlers(lpparam, appId)
//            hookedAppIds.add(appId)
//        }
//    }

    private fun log(message: String) {
        XposedBridge.log(message)
        synchronized(logList) {
            if (logList.size >= maxLogSize) {
                logList.removeAt(0)
            }
            logList.add(message)
        }
    }

    private fun startServer() {
        log("$label start embeddedServer at 0.0.0.0:59999")
        embeddedServer(Netty, port = 59999) {
            install(ContentNegotiation) {
                gson {
                    setPrettyPrinting()
                }
            }
            install(StatusPages) {
                exception<Throwable> { cause ->
                    call.respond(HttpStatusCode.InternalServerError, cause.localizedMessage)
                }
            }
            routing {
                get("/") {
                    call.respond("ok")
                }
                post("/CallWX") {
                    val request = call.receive<CallWXRequest>()
                    if (request.appid.isNotEmpty() && request.jsapi_name.isNotEmpty() && request.data.isNotEmpty()) {
                        val response = callWX(request.appid, request.jsapi_name, request.data)
                        call.respond(mapOf("result" to response))
                    } else {
                        call.respond(HttpStatusCode.BadRequest, "Missing parameters")
                    }
                }
                get("/wx_log") {
                    call.respond(logList)
                }
            }
        }.start(wait = false)
    }

    private fun callWX(appid: String, jsapiName: String, data: String): String {
        callAppId = appid
        callWXAsyncRequestCounter++
        log("$label receive callWX api data，to do invokeMethod")
        log("$label check appBrandCommonBindingJniInstance cache: $appBrandCommonBindingJniInstance")
        appBrandCommonBindingJniInstance?.let {
            try {
                val invokeMethod = it::class.java.getMethod(
                    "nativeInvokeHandler",
                    String::class.java,
                    String::class.java,
                    String::class.java,
                    Int::class.java,
                    Boolean::class.java,
                    Int::class.java,
                    Int::class.java
                )
                invokeMethod.isAccessible = true
                invokeMethod.invoke(
                    it,
                    jsapiName,
                    data,
                    "{}",
                    callWXAsyncRequestCounter,
                    true,
                    0,
                    0
                )
                log("$label invokeMethod success: $callAppId-$callWXAsyncRequestCounter")
            } catch (e: Exception) {
                log("$label Exception in callWX with cached instance: ${e.message}")
            }
        } ?: log("$label AppBrandCommonBindingJniInstance is null")

        return "$callAppId-$callWXAsyncRequestCounter"
    }
}