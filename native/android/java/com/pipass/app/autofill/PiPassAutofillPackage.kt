package com.pipass.app.autofill

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager

/**
 * React Native package that registers [PiPassAutofillModule].
 *
 * Wired into the app via [com.pipass.app.MainApplication]'s package list,
 * which is patched at prebuild time by `plugins/withAutofillModule.js`.
 */
class PiPassAutofillPackage : ReactPackage {

    override fun createNativeModules(reactContext: ReactApplicationContext): List<NativeModule> {
        return listOf(PiPassAutofillModule(reactContext))
    }

    override fun createViewManagers(reactContext: ReactApplicationContext): List<ViewManager<*, *>> {
        return emptyList()
    }
}
