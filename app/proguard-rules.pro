-keep class com.example.jarvis.** { *; }
-keepclassmembers class * {
    *** onAccessibilityEvent(...);
    *** onInterrupt();
}
-dontwarn java.lang.invoke.*
-dontwarn javax.crypto.**
