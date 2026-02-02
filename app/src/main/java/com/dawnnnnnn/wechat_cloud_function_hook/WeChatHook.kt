package com.dawnnnnnn.wechat_cloud_function_hook

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.features.ContentNegotiation
import io.ktor.features.StatusPages
import io.ktor.gson.gson
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.request.receive
import io.ktor.response.respond
import io.ktor.response.respondText
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger


data class InvokeRequest(
    val appId: String,
    val api: String,
    val data: String,
    val extra: String = "{}",
    val isSync: Boolean = false,
    val arg7: Int = -1
)

class WeChatHook : IXposedHookLoadPackage, IXposedHookZygoteInit {

    private var serverStarted = false
    private var invokeAsyncRequestCounter = AtomicInteger(0)
    private var callAppId: String? = null
    private val hookedAppIds = mutableSetOf<String>()
    private val label = "[WeFaaS]"
    private val logList = mutableListOf<String>()
    private val maxLogSize = 1500

    @Volatile
    private var appBrandCommonBindingJniInstance: Any? = null

    // Store pending requests: CallbackID -> Deferred Result
    private val pendingRequests = ConcurrentHashMap<Int, CompletableDeferred<String>>()

    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {

    }

    private fun setupHooks(lpparam: XC_LoadPackage.LoadPackageParam) {
        // Target the AppBrand processes
        if (!lpparam.processName.contains("com.tencent.mm:appbrand")) return

        log("$label Active in process ${lpparam.processName}. Waiting for UI to trigger hooks...")

        // 1. Hook the base Activity onCreate.
        // This is the "Frida trigger": once the mini-program UI exists, the engine MUST be loaded.
        XposedHelpers.findAndHookMethod("android.app.Activity",
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
            })
    }

    private fun injectRealHooks(classLoader: ClassLoader): Boolean {
        var success = false
        try {
            // --- HOOK 1: REQUEST (nativeInvokeHandler) ---
            // As per your JADX screenshot: String, String, String, int, boolean, int, int
            XposedHelpers.findAndHookMethod("com.tencent.mm.appbrand.commonjni.AppBrandCommonBindingJni",
                classLoader,
                "nativeInvokeHandler",
                String::class.java,           // api
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
                        val no = param.args[3] as Int
                        if (no > 0) log("[REQ] #$no -> $api | $data | ${
                            param.args.drop(2).joinToString { it?.toString() ?: "null" }
                        }")
                    }
                })
            log("$label Hooked Request successfully.")
            success = true
        } catch (e: Throwable) {
            log("$label Failed to hook Request: ${e.message}")
        }

        try {
            // --- HOOK 2: RESPONSE (invokeCallbackHandler) ---
            // Your JADX shows 3 params: (int, String, String)
            XposedHelpers.findAndHookMethod("com.tencent.mm.appbrand.commonjni.AppBrandJsBridgeBinding",
                classLoader,
                "invokeCallbackHandler",
                "int",              // callbackId
                String::class.java, // result
                String::class.java, // extra
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val id = param.args[0] as Int
                        val res = param.args[1] as String
                        log("[RES] #$id <- $res | ${
                            param.args.drop(2).joinToString { it?.toString() ?: "null" }
                        }")
                        // Update our counter to match the system's counter if provided
                        val current = invokeAsyncRequestCounter.get()
                        if (id > current) {
                            invokeAsyncRequestCounter.set(id)
                        }

                        // Check if this is a response for our active call
                        if (pendingRequests.containsKey(id)) {
                            log("$label [RES] Match found for ID: $id")
                            pendingRequests[id]?.complete(res)
                        }
                    }
                })
            log("$label Hooked Response successfully.")
            success = true
        } catch (e: Throwable) {
            log("$label Failed to hook Response: ${e.message}")
        }

        // --- HOOK 3: OBTAIN AppID (com.tencent.mm.plugin.appbrand.y.getAppId) ---
        // Based on Frida script: v["getAppId"].implementation ...
        try {
            XposedHelpers.findAndHookMethod("com.tencent.mm.plugin.appbrand.y",
                classLoader,
                "getAppId",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val appId = param.result
                        if (appId != null && callAppId == null) {
                            callAppId = appId as String
                            log("$label Found AppID: $callAppId")
                            startServerIfNeeded()
                        }
                    }
                })
            log("$label Hooked getAppId successfully.")
        } catch (e: Throwable) {
            log("$label Failed to hook getAppId (checking 'y'): ${e.message}")
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
        log("$label Starting server on 0.0.0.0:59999")
        embeddedServer(Netty, port = 59999) {
            install(ContentNegotiation) {
                gson {
                    setPrettyPrinting()
                }
            }
            install(StatusPages) {
                exception<Throwable> { cause ->
                    call.respond(HttpStatusCode.InternalServerError, "${cause.localizedMessage}\n${cause.stackTraceToString()}")
                }
            }
            routing {
                get("/") {
                    call.respond("ok")
                }
                post("/invoke") {
                    val request = call.receive<InvokeRequest>()
                    if (request.appId.isNotEmpty() && request.api.isNotEmpty() && request.data.isNotEmpty()) {
                        try {
                            val response = invoke(
                                request.appId,
                                request.api,
                                request.data,
                                request.extra,
                                request.isSync,
                                request.arg7
                            )
                            call.respondText(response, ContentType.Application.Json)
                        } catch (e: Exception) {
                            call.respond(HttpStatusCode.InternalServerError, "Error: ${e.message}")
                        }
                    } else {
                        call.respond(HttpStatusCode.BadRequest, "Missing parameters")
                    }
                }
                get("/logs") {
                    call.respond(logList)
                }
            }
        }.start(wait = false)
    }

    private suspend fun invoke(
        appId: String,
        jsapiName: String,
        data: String,
        extra: String = "{}",
        isSync: Boolean = false,
        arg7: Int = -1
    ): String {
        val instance = appBrandCommonBindingJniInstance
        if (instance == null) {
            val msg = "AppBrandCommonBindingJniInstance is null. Please open a Mini Program first."
            log("$label $msg")
            throw IllegalStateException(msg)
        }

        callAppId = appId
        val requestId = invokeAsyncRequestCounter.incrementAndGet()
        val deferred = CompletableDeferred<String>()
        pendingRequests[requestId] = deferred

        log("$label [Dispatch] ID: $requestId | API: $jsapiName")

        try {
            val invokeMethod = instance::class.java.getMethod(
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
                instance, jsapiName, data, extra, requestId, isSync, 0, arg7
            )

            // Wait for response
            return withTimeout(10000L) {
                deferred.await()
            }

        } catch (e: Exception) {
            log("$label Exception in invoke: ${e.message}")
            throw e
        } finally {
            pendingRequests.remove(requestId)
            callAppId = null
        }
    }
}